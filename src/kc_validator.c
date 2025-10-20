/*
Copyright © contributors to CloudNativePG, established as
CloudNativePG a Series of LF Projects, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
*/
#include "postgres.h"
#include "fmgr.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "common/base64.h"
#include "libpq/oauth.h"
#include <curl/curl.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

PG_MODULE_MAGIC;

static char *kc_token_endpoint  = NULL;
static char *kc_audience        = NULL;
static char *kc_resource_name   = NULL;
static char *kc_client_id       = NULL;
static int   kc_http_timeout_ms = 2000;
static char *kc_expected_issuer = NULL;
static bool  kc_debug           = false;
static bool  kc_log_body        = false;

typedef struct
{
    char *data;
    size_t len;
} CurlBuf;

static size_t
write_cb(void *contents, size_t sz, size_t nm, void *userp)
{
    char *p;
    size_t n;
    CurlBuf *b;
    n = sz * nm;
    b = (CurlBuf *) userp;

    p = (char *) repalloc(b->data, b->len + n + 1);
    if (!p)
        return 0;

    b->data = p;
    memcpy(b->data + b->len, contents, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

static bool
json_has_result_true(const char *json)
{
    const char *p;
    char c;
    if (!json) return false;
    p = strstr(json, "\"result\"");
    if (!p) return false;
    p = strchr(p, ':'); if (!p) return false;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncmp(p, "true", 4) != 0) return false;
    c = p[4];
    return (c == '\0' || c == ',' || c == '}' || isspace((unsigned char)c));
}

static const char *
redact_tail_buf(const char *s, char *buf, size_t buflen)
{
    size_t len;
    size_t keep;
    size_t i;
    size_t j;
    if (!s) return "<null>";
    len = strlen(s);
    keep = (len > 4) ? 4 : len;
    i = 0;
    for (; i < len - keep && i < buflen - 1; i++) buf[i] = '*';
    for (j = 0; j < keep && i < buflen - 1; j++, i++) buf[i] = s[len - keep + j];
    buf[i] = '\0';
    return buf;
}

static char *
base64url_decode_to_str(const char* in)
{
    size_t len;
    char *tmp;
    int pad;
    int outlen;
    uint8 *out;
    int n;
    len = strlen(in);
    tmp = pstrdup(in);
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == '-') tmp[i] = '+';
        else if (tmp[i] == '_') tmp[i] = '/';
    }
    pad = (4 - (len % 4)) % 4;
    tmp = repalloc(tmp, len + pad + 1);
    for (int i = 0; i < pad; i++) tmp[len + i] = '=';
    tmp[len + pad] = '\0';
  
    outlen = pg_b64_dec_len(len + pad);
    out = palloc(outlen + 1);
    n = pg_b64_decode(tmp, (int)(len + pad), out, outlen);
    pfree(tmp);
    if (n < 0) { pfree(out); return NULL; }
    ((char*)out)[n] = '\0';
    return (char*)out;
}

static bool
issuer_ok(const char *token)
{
    if (!kc_expected_issuer) {
        if (kc_debug) elog(DEBUG1, "kc: issuer_ok: expected_issuer not set -> skip");
        return true;
    }

    const char *dot1;
    const char *dot2;
    size_t payload_len;
    char *payload_b64;
    char *payload_json;
    const char *k;
    const char *start;
    size_t iss_len;
    bool ok;
    if (!token || !*token) return false;

    dot1 = strchr(token, '.');
    if (!dot1) return false;
    dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return false;

    payload_len = (size_t)(dot2 - (dot1 + 1));
    payload_b64 = pnstrdup(dot1 + 1, payload_len);
    payload_json = base64url_decode_to_str(payload_b64);
    pfree(payload_b64);
    if (!payload_json) return false;

    k = strstr(payload_json, "\"iss\"");
    if (!k) { pfree(payload_json); return false; }
    k = strchr(k, ':'); if (!k) { pfree(payload_json); return false; }
    k++;
    while (*k && isspace((unsigned char)*k)) k++;
    if (*k != '\"') { pfree(payload_json); return false; }
    k++;
    start = k;
    while (*k && *k != '\"') k++;
    iss_len = (size_t)(k - start);

    ok = (iss_len == strlen(kc_expected_issuer) &&
               strncmp(start, kc_expected_issuer, iss_len) == 0);

    if (kc_debug) elog(DEBUG1, "kc: issuer_ok=%s", ok ? "true" : "false");
    pfree(payload_json);

    return ok;
}

static inline bool add_hdr(struct curl_slist **hdr, const char *line)
{
    struct curl_slist *tmp = curl_slist_append(*hdr, line);
    if (!tmp) return false;
    *hdr = tmp;
    return true;
}

static bool
kc_decision(CURL *curl, const char *permission, const char *user_token)
{
    CurlBuf buf;
    struct curl_slist *hdr;
    long tmo;
    bool ok;
    CURLcode rc;
    char errbuf[CURL_ERROR_SIZE] = {0};
    long http_code;
    double total_time;
    char *aud;
    char *perm_enc;
    char *cid;
    char *post;
    long connect_tmo;

    buf.data = palloc0(1);
    buf.len  = 0;
    hdr = NULL;
    tmo = (long) kc_http_timeout_ms;
    ok = false;
    http_code = 0;
    total_time = 0.0;

    if (!kc_token_endpoint || !kc_audience || !permission ||
        !kc_client_id)
    {
        if (kc_debug)
            elog(DEBUG1, "kc: kc_decision: missing required params "
                         "(endpoint=%s, audience=%s, permission=%s, client_id=%s)",
                 kc_token_endpoint ? "set" : "NULL",
                 kc_audience ? "set" : "NULL",
                 permission ? permission : "NULL",
                 kc_client_id ? "set" : "NULL");
        if (buf.data) pfree(buf.data);
        return false;
    }

    hdr = NULL;
    if (!add_hdr(&hdr, "Content-Type: application/x-www-form-urlencoded")) goto err;
    if (!add_hdr(&hdr, "Accept: application/json")) goto err;
    if (!add_hdr(&hdr, "Expect:")) goto err;
    if (user_token && *user_token) {
        char *auth = psprintf("Authorization: Bearer %s", user_token);
        bool added = add_hdr(&hdr, auth);
        pfree(auth);
        if (!added) goto err;
    }

    aud = curl_easy_escape(curl, kc_audience, 0);
    perm_enc = curl_easy_escape(curl, permission, 0);
    cid = curl_easy_escape(curl, kc_client_id, 0);
    if (!aud || !perm_enc || !cid) {
        if (aud) curl_free(aud);
        if (perm_enc) curl_free(perm_enc);
        if (cid) curl_free(cid);
        curl_slist_free_all(hdr);
        if (buf.data) pfree(buf.data);
        return false;
    }

    post = psprintf(
        "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket"
        "&audience=%s&permission=%s&response_mode=decision&client_id=%s",
        aud, perm_enc, cid);

    curl_free(aud);
    curl_free(perm_enc);
    curl_free(cid);

    if (kc_debug) {
        char cid_red[128];
        elog(DEBUG1, "kc: decision request -> URL=%s, audience=%s, permission=%s, timeout_ms=%ld, client_id=%s",
             kc_token_endpoint,
             kc_audience,
             permission,
             tmo,
             redact_tail_buf(kc_client_id, cid_red, sizeof(cid_red)));
    }

    connect_tmo = tmo / 2;
    if (connect_tmo < 100) connect_tmo = 100;

    curl_easy_setopt(curl, CURLOPT_URL, kc_token_endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(post));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, tmo);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connect_tmo);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &buf);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "kc_validator/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 512L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 3L);

    rc = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    if (rc == CURLE_OK && http_code == 200) {
        ok = json_has_result_true(buf.data);
    } else {
        ok = false;
    }
    
    if (kc_debug) {
        elog(DEBUG1,
             "kc: decision resp http=%ld time=%.1fms body_len=%ld decision=%s rc=%d(%s) err=\"%s\"",
             http_code, total_time * 1000.0, (long) buf.len, ok ? "true" : "false",
             (int) rc, curl_easy_strerror(rc), errbuf[0] ? errbuf : "(no detail)");
        
        if (kc_log_body && buf.data) {
            int max = 2048;
            int len = (int) strlen(buf.data);
            elog(DEBUG1, "kc: response body: %.*s%s",
                 (len > max ? max : len), buf.data,
                 (len > max ? " ...<truncated>" : ""));
        }
    }

    if (post) pfree(post);
    if (buf.data) pfree(buf.data);
    if (hdr) curl_slist_free_all(hdr);

    return ok;

err:
    if (buf.data) pfree(buf.data);
    if (hdr) curl_slist_free_all(hdr);
    return false;
}

static char *
jwt_get_claim_string(const char *token, const char *key)
{
    const char *dot1;
    const char *dot2;
    size_t payload_len;
    char *payload_b64;
    char *payload_json;
    char pat[64];
    const char *k;
    const char *start;
    size_t vlen;
    char *val;
    if (!token || !*token || !key) return NULL;

    dot1 = strchr(token, '.');
    if (!dot1) return NULL;
    dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return NULL;

    payload_len = (size_t)(dot2 - (dot1 + 1));
    payload_b64 = pnstrdup(dot1 + 1, payload_len);
    payload_json = base64url_decode_to_str(payload_b64);
    pfree(payload_b64);
    if (!payload_json) return NULL;

    snprintf(pat, sizeof(pat), "\"%s\"", key);
    k = strstr(payload_json, pat);
    if (!k) { pfree(payload_json); return NULL; }
    k = strchr(k, ':'); if (!k) { pfree(payload_json); return NULL; }
    k++;
    while (*k && isspace((unsigned char)*k)) k++;
    if (*k != '\"') { pfree(payload_json); return NULL; }
    k++;
    start = k;
    while (*k && *k != '\"') k++;
    vlen = (size_t)(k - start);

    val = (char *) palloc(vlen + 1);
    memcpy(val, start, vlen);
    val[vlen] = '\0';
    pfree(payload_json);
    return val;
}

static bool
validate_token(const ValidatorModuleState *state,
               const char *token, const char *role,
               ValidatorModuleResult *res)
{
    char *perm = NULL;
    CURL *curl;
    bool decision;

    (void) state;

    res->authorized = false;
    res->authn_id   = NULL;

    if (kc_debug)
        elog(DEBUG1, "kc: validate_token: token=%s, role=%s, resource_name=%s",
             token ? "(present)" : "(NULL)",
             role ? role : "(NULL)",
             kc_resource_name ? kc_resource_name : "(NULL)");

    if (!token || !role || !kc_resource_name)
    {
        if (kc_debug)
            elog(DEBUG1, "kc: early return: missing one of (token, role, resource_name)");
        return true;
    }

    if (!issuer_ok(token))
    {
        if (kc_debug)
            elog(DEBUG1, "kc: issuer check failed -> deny");
        return true;
    }
    res->authn_id   = jwt_get_claim_string(token, "sub");

    curl = curl_easy_init();
    if (!curl)
    {
        if (kc_debug)
            elog(DEBUG1, "kc: curl_easy_init failed");
        return true;
    }
    perm = psprintf("%s#%s", kc_resource_name, role);

    if (kc_debug)
        elog(DEBUG1, "kc: calling kc_decision with perm=\"%s\"", perm);

    decision = kc_decision(curl, perm, token);
    curl_easy_cleanup(curl);

    if (decision)
    {
        res->authorized = true;
        if (kc_debug)
            elog(DEBUG1, "kc: authorization = TRUE for perm=\"%s\"", perm);
    }
    else
    {
        if (kc_debug)
            elog(DEBUG1, "kc: authorization = FALSE for perm=\"%s\"", perm);
    }

    if (perm) pfree(perm);

    return true;
}

static void
validator_startup(ValidatorModuleState *s)
{
    const char *ver;
    (void) s;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ver = curl_version();
    if (kc_debug)
        elog(DEBUG1, "kc: validator_startup: libcurl=%s, timeout_ms=%d", ver ? ver : "unknown", kc_http_timeout_ms);
}

static void
validator_shutdown(ValidatorModuleState *s)
{
    (void) s;
    curl_global_cleanup();
    if (kc_debug)
        elog(DEBUG1, "kc: validator_shutdown");
}

static const OAuthValidatorCallbacks KC = {
    .magic       = PG_OAUTH_VALIDATOR_MAGIC,
    .startup_cb  = validator_startup,
    .shutdown_cb = validator_shutdown,
    .validate_cb = validate_token,
};

const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
    return &KC;
}

void
_PG_init(void)
{
    DefineCustomStringVariable("kc.token_endpoint",
        "Keycloak token endpoint for UMA decision", NULL,
        &kc_token_endpoint, NULL, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("kc.audience",
        "Keycloak audience (resource-server client ID)", NULL,
        &kc_audience, NULL, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("kc.resource_name",
        "Permission resource part (<resource>#<role>)", NULL,
        &kc_resource_name, NULL, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("kc.client_id",
        "Client ID for UMA decision call", NULL,
        &kc_client_id, NULL, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("kc.http_timeout_ms",
        "HTTP timeout in milliseconds", NULL,
        &kc_http_timeout_ms, 2000, 100, 60000, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("kc.expected_issuer",
        "Expected issuer to verify token 'iss' (optional)", NULL,
        &kc_expected_issuer, NULL, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("kc.debug",
        "Enable verbose debug logging (no secrets)", NULL,
        &kc_debug, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("kc.log_body",
        "Log HTTP response body (may contain sensitive info)", NULL,
        &kc_log_body, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

    MarkGUCPrefixReserved("kc");
}
