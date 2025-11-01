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

/* -----------------------------------------------------------------------------
 * Configurable parameters via GUC:
 *
 * kc.token_endpoint   : Full URL of Keycloak token endpoint used for the decision.
 *                       Example:
 *                       https://kc.example.com/realms/demo/protocol/openid-connect/token
 *
 * kc.audience         : Target resource-server client ID (audience) for the decision.
 *
 * kc.resource_name    : Resource identifier used to build the permission string
 *                       together with "scope" as "<resource>#<scope>".
 *                       (Note: The 'role' parameter in code corresponds to Keycloak 'scope'.)
 *
 * kc.client_id        : Client ID included in the token request.
 *
 * kc.http_timeout_ms  : Total HTTP timeout (ms). Connect timeout is half of this,
 *                       with a minimum of 100ms.
 *
 * kc.expected_issuer  : Optional issuer to verify the JWT "iss" claim.
 *                       Example:
 *                       https://kc.example.com/realms/demo
 *
 * kc.debug            : Verbose debug logging (no secrets).
 *
 * kc.log_body         : If true, logs HTTP response body (may contain sensitive info).
 * --------------------------------------------------------------------------- */

static char *kc_token_endpoint  = NULL;
static char *kc_audience        = NULL;
static char *kc_resource_name   = NULL;
static char *kc_client_id       = NULL;
static int   kc_http_timeout_ms = 2000;
static char *kc_expected_issuer = NULL;
static bool  kc_debug           = false;
static bool  kc_log_body        = false;
static bool  kc_insecure = false;

/**
 * @brief A growable buffer for storing libcurl response data.
 */
typedef struct
{
    char *data; /**< Buffer data (palloc'd) */
    size_t len; /**< Current length of data in buffer */
} CurlBuf;

/**
 * @brief libcurl write callback (CURLOPT_WRITEFUNCTION).
 *
 * Appends the received data chunk to the CurlBuf buffer, reallocating
 * it as needed.
 *
 * @param contents Pointer to the received data chunk.
 * @param sz       Size of one data element (usually 1 byte).
 * @param nm       Number of data elements.
 * @param userp    Pointer to the CurlBuf struct to append to.
 * @return         Number of bytes consumed (sz * nm), or 0 on repalloc failure.
 */
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
        return 0; /* Signal error to libcurl */

    b->data = p;
    memcpy(b->data + b->len, contents, n);
    b->len += n;
    b->data[b->len] = '\0'; /* Always NUL-terminate */
    return n;
}

/**
 * @brief Performs a minimal JSON check for the presence of {"result": true}.
 *
 * This function avoids linking a full JSON parser. It simply scans for the
 * literal string "result", finds the ':', skips whitespace, and verifies
 * the value is the literal string "true", followed by a valid delimiter
 * (',', '}', whitespace, or end-of-string).
 *
 * @param json The JSON string (e.g., HTTP response body).
 * @return true if '{"result": true}' is reliably detected, false otherwise.
 */
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
    while (*p && isspace((unsigned char)*p)) p++; /* Skip whitespace */
    if (strncmp(p, "true", 4) != 0) return false;
    c = p[4];
    /* Check for valid JSON delimiters after "true" */
    return (c == '\0' || c == ',' || c == '}' || isspace((unsigned char)c));
}

/**
 * @brief Redacts a string, preserving only the last (up to) 4 characters.
 *
 * Example: "abcdef" -> "**cdef"
 *
 * @param s       Input string (may be NULL).
 * @param buf     Destination buffer.
 * @param buflen  Destination buffer length.
 * @return        Pointer to buf, or "<null>" if s is NULL.
 */
static const char *
redact_tail_buf(const char *s, char *buf, size_t buflen)
{
    size_t len;
    size_t keep;
    size_t i;
    size_t j;
    if (!s) return "<null>";
    len = strlen(s);
    keep = (len > 4) ? 4 : len; /* Keep at most 4 chars */
    i = 0;
    /* Fill with '*' */
    for (; i < len - keep && i < buflen - 1; i++) buf[i] = '*';
    /* Append the kept tail */
    for (j = 0; j < keep && i < buflen - 1; j++, i++) buf[i] = s[len - keep + j];
    buf[i] = '\0';
    return buf;
}

/**
 * @brief Decodes a base64url-encoded string into a NUL-terminated string.
 *
 * This function converts base64url to standard base64 (replaces '-' with '+'
 * and '_' with '/'), adds necessary '=' padding, and then uses PostgreSQL's
 * built-in base64 decoder.
 *
 * @param in  The base64url-encoded input string.
 * @return    A palloc'd, NUL-terminated string on success.
 * NULL on decoding failure.
 * The caller is responsible for pfree'ing the returned string.
 */
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

    /* Convert base64url alphabet to standard base64 */
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == '-') tmp[i] = '+';
        else if (tmp[i] == '_') tmp[i] = '/';
    }

    /* Add standard base64 padding */
    pad = (4 - (len % 4)) % 4;
    tmp = repalloc(tmp, len + pad + 1);
    for (int i = 0; i < pad; i++) tmp[len + i] = '=';
    tmp[len + pad] = '\0';

    /* Decode using PostgreSQL's built-in function */
    outlen = pg_b64_dec_len(len + pad);
    out = palloc(outlen + 1);
    n = pg_b64_decode(tmp, (int)(len + pad), out, outlen);
    pfree(tmp);
    if (n < 0) {
      pfree(out);
      return NULL; /* Decode error */
    }
    ((char*)out)[n] = '\0'; /* NUL-terminate */
    return (char*)out;
}

/**
 * @brief Verifies the "iss" (issuer) claim in a JWT against the
 * kc_expected_issuer GUC.
 *
 * This function performs *no* signature validation. It only decodes the
 * base64url payload (the second part of the JWT) and performs a minimal
 * string scan to extract the "iss" field, avoiding a full JSON parse.
 *
 * @param token  The raw JWT string (header.payload.signature).
 * @return       true if the issuer matches kc_expected_issuer,
 * or if kc_expected_issuer is not set (check disabled).
 * false on mismatch or if the "iss" claim cannot be parsed.
 */
static bool
issuer_ok(const char *token)
{
    /* If GUC is not set, skip the check */
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

    /* Find the first dot (after header) */
    dot1 = strchr(token, '.');
    if (!dot1) return false;
    /* Find the second dot (after payload) */
    dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return false;

    /* Extract the base64url payload string */
    payload_len = (size_t)(dot2 - (dot1 + 1));
    payload_b64 = pnstrdup(dot1 + 1, payload_len);
    payload_json = base64url_decode_to_str(payload_b64);
    pfree(payload_b64);
    if (!payload_json) return false;

    /* Minimal JSON parse: find '"iss"':"value" */
    k = strstr(payload_json, "\"iss\"");
    if (!k) { pfree(payload_json); return false; }
    k = strchr(k, ':'); if (!k) { pfree(payload_json); return false; }
    k++;
    while (*k && isspace((unsigned char)*k)) k++; /* Skip whitespace */
    if (*k != '\"') { pfree(payload_json); return false; } /* Must be a string */
    k++;
    start = k;
    while (*k && *k != '\"') k++; /* Find end quote */
    iss_len = (size_t)(k - start);

    /* Compare the extracted issuer with the expected one */
    ok = (iss_len == strlen(kc_expected_issuer) &&
               strncmp(start, kc_expected_issuer, iss_len) == 0);

    if (kc_debug) elog(DEBUG1, "kc: issuer_ok=%s", ok ? "true" : "false");
    pfree(payload_json);

    return ok;
}

/**
 * @brief Appends a formatted header string to a curl_slist.
 *
 * This is a simple wrapper around curl_slist_append to simplify error checking.
 *
 * @param hdr    Pointer to the curl_slist* (will be updated on success).
 * @param line   Header line string (e.g., "Accept: application/json").
 * @return       true on success, false on append failure.
 */
static inline bool add_hdr(struct curl_slist **hdr, const char *line)
{
    struct curl_slist *tmp = curl_slist_append(*hdr, line);
    if (!tmp) return false;
    *hdr = tmp;
    return true;
}

/**
 * @brief Performs a Keycloak UMA ticket decision request.
 *
 * This function builds an x-www-form-urlencoded POST request to the
 * Keycloak token endpoint (`kc.token_endpoint`) with the following
 * UMA-specific parameters:
 *
 * grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
 * audience=<kc_audience>
 * permission=<resource>#<scope>
 * response_mode=decision
 * client_id=<kc_client_id>
 * Authorization: Bearer <user_token>
 *
 * @param curl         Initialized CURL* handle (easy interface).
 * @param permission   The permission string, formatted as "<resource>#<scope>".
 * @param user_token   The end-user's access token (JWT).
 * @return             true if the HTTP response is 200 OK and the body
 * contains {"result": true}, false otherwise.
 *
 * Timeouts:
 * - CURLOPT_TIMEOUT_MS = kc_http_timeout_ms
 * - CURLOPT_CONNECTTIMEOUT_MS = kc_http_timeout_ms / 2 (min 100ms)
 *
 * TLS:
 * - Peer and host verification are enabled (CURLOPT_SSL_VERIFYPEER,
 * CURLOPT_SSL_VERIFYHOST).
 */
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
    char *aud = NULL;
    char *perm_enc = NULL;
    char *cid = NULL;
    char *post = NULL;
    long connect_tmo;

    /* Initialize response buffer (must be pfree'd) */
    buf.data = palloc0(1);
    buf.len  = 0;
    hdr = NULL;
    tmo = (long) kc_http_timeout_ms;
    ok = false;
    http_code = 0;
    total_time = 0.0;

    /* Check that all required GUC parameters are set */
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

    /* Build HTTP headers */
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

    /* URL-encode POST body components */
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

    /* Build the POST body */
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

    /* Calculate connect timeout: half of total, but at least 100ms */
    connect_tmo = tmo / 2;
    if (connect_tmo < 100) connect_tmo = 100;

    /* --- Configure libcurl options --- */
    curl_easy_setopt(curl, CURLOPT_URL, kc_token_endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(post));

    /* Set connection and total timeouts */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, tmo);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, connect_tmo);

    /* Disable signals (important for timeouts in multi-threaded/signal-heavy apps) */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf); /* Capture error details */

    /* Set up response buffer callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &buf);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "kc_validator/1.0");

    /* Enforce TLS certificate and hostname verification */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, kc_insecure ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, kc_insecure ? 2L : 0L);

    /* Fail hard on HTTP 4xx/5xx responses (e.g., 401, 403, 500) */
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    /* Protect against very slow/stalled connections */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 512L); /* 512 bytes/sec */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 3L); /* must maintain for 3s */
    /* --- End of libcurl options --- */

    rc = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    /*
     * Success is defined as:
     * 1. libcurl request completed (rc == CURLE_OK)
     * 2. HTTP status code was 200
     * 3. Response body contained {"result": true}
     *
     * Note: CURLOPT_FAILONERROR handles 4xx/5xx, so we only expect 200 here
     * on a successful (CURLE_OK) request.
     */
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
            int max = 2048; /* Truncate long bodies in logs */
            int len = (int) strlen(buf.data);
            elog(DEBUG1, "kc: response body: %.*s%s",
                 (len > max ? max : len), buf.data,
                 (len > max ? " ...<truncated>" : ""));
        }
    }

    /* Cleanup */
    if (post) pfree(post);
    if (buf.data) pfree(buf.data);
    if (hdr) curl_slist_free_all(hdr);

    return ok;

err: /* Error path for setup failures (e.g., add_hdr, curl_easy_escape) */
    if (kc_debug) elog(DEBUG1, "kc: decision setup failed (e.g., header append)");
    if (post) pfree(post); /* post might not be set, but pfree(NULL) is safe */
    if (buf.data) pfree(buf.data);
    if (hdr) curl_slist_free_all(hdr);
    return false;
}

/**
 * @brief Extracts a string claim value from a JWT payload by its key.
 *
 * This function performs *no* signature validation. It decodes the
 * base64url payload and performs a minimal string scan to find the key
 * (e.g., "sub") and extract the subsequent quoted string value.
 *
 * @param token  The raw JWT string (header.payload.signature).
 * @param key    The JSON claim name to extract (e.g., "sub").
 * @return       A palloc'd string containing the claim value,
 * or NULL if the token/key is invalid or the claim is not found.
 * The caller is responsible for pfree'ing the returned string.
 */
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

    /* Find payload (part between dots) */
    dot1 = strchr(token, '.');
    if (!dot1) return NULL;
    dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return NULL;

    payload_len = (size_t)(dot2 - (dot1 + 1));
    payload_b64 = pnstrdup(dot1 + 1, payload_len);
    payload_json = base64url_decode_to_str(payload_b64);
    pfree(payload_b64);
    if (!payload_json) return NULL;

    /* Build search pattern: "key" */
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    k = strstr(payload_json, pat);
    if (!k) { pfree(payload_json); return NULL; }

    /* Find value: :"value" */
    k = strchr(k, ':'); if (!k) { pfree(payload_json); return NULL; }
    k++;
    while (*k && isspace((unsigned char)*k)) k++; /* Skip whitespace */
    if (*k != '\"') { pfree(payload_json); return NULL; } /* Must be string */
    k++;
    start = k;
    while (*k && *k != '\"') k++; /* Find end quote */
    vlen = (size_t)(k - start);

    /* Allocate and copy the value */
    val = (char *) palloc(vlen + 1);
    memcpy(val, start, vlen);
    val[vlen] = '\0';
    pfree(payload_json);
    return val;
}

/**
 * @brief Main validator callback: authenticates and authorizes a token for a scope.
 *
 * This function is the core implementation of the OAuthValidatorCallbacks.
 * The 'role' parameter in code corresponds to Keycloak 'scope'.
 *
 * Steps:
 * 1) Fast-fail if token, role, or resource_name GUC are missing.
 * 2) (Optional) Verify the token's "iss" claim against `kc.expected_issuer`.
 * 3) Extract the "sub" (subject) claim as the `authn_id` for auditing.
 * 4) Compute the permission string as "<kc.resource_name>#<role>".
 * 5) Call kc_decision() to get the authorization decision from Keycloak.
 * 6) Set `res->authorized` based on the Keycloak decision.
 *
 * @param state  Unused module state (reserved for future).
 * @param token  The end-user's access token (JWT).
 * @param role   The logical role (Keycloak 'scope') to check.
 * @param res    Output struct to be populated:
 * - res->authorized is set to true on success.
 * - res->authn_id is set to the palloc'd "sub" claim.
 * @return       Always returns true to indicate the check was handled by this
 * module. The *actual* authorization decision is in res->authorized.
 */
static bool
validate_token(const ValidatorModuleState *state,
               const char *token, const char *role,
               ValidatorModuleResult *res)
{
    char *perm = NULL;
    CURL *curl;
    bool decision;

    (void) state; /* Unused */

    /* Default to unauthorized */
    res->authorized = false;
    res->authn_id   = NULL;

    if (kc_debug)
        elog(DEBUG1, "kc: validate_token: token=%s, role=%s, resource_name=%s",
             token ? "(present)" : "(NULL)",
             role ? role : "(NULL)",
             kc_resource_name ? kc_resource_name : "(NULL)");

    /* If any required param is missing, we must deny */
    if (!token || !role || !kc_resource_name)
    {
        if (kc_debug)
            elog(DEBUG1, "kc: early return: missing one of (token, role, resource_name)");
        return true; /* Handled (by denying) */
    }

    /* 1. (Optional) Issuer Check */
    if (!issuer_ok(token))
    {
        if (kc_debug)
            elog(DEBUG1, "kc: issuer check failed -> deny");
        return true; /* Handled (by denying) */
    }

    /* 2. Extract subject for audit/logging (authn_id) */
    res->authn_id   = jwt_get_claim_string(token, "sub");

    /* 3. Initialize libcurl */
    curl = curl_easy_init();
    if (!curl)
    {
        if (kc_debug)
            elog(DEBUG1, "kc: curl_easy_init failed");
        return true; /* Handled (by denying) */
    }
    perm = psprintf("%s#%s", kc_resource_name, role);

    if (kc_debug)
        elog(DEBUG1, "kc: calling kc_decision with perm=\"%s\"", perm);

    /* 5. Perform the UMA decision request */
    decision = kc_decision(curl, perm, token);
    curl_easy_cleanup(curl);

    /* 6. Set final result */
    if (decision)
    {
        res->authorized = true;
        if (kc_debug)
            elog(DEBUG1, "kc: authorization = TRUE for perm=\"%s\"", perm);
    }
    else
    {
        /* res->authorized is already false */
        if (kc_debug)
            elog(DEBUG1, "kc: authorization = FALSE for perm=\"%s\"", perm);
    }

    if (perm) pfree(perm);


    /*
     * We return true to tell the caller that we *handled* the validation.
     * The actual outcome is in res->authorized.
     */
    return true;
}

/**
 * @brief Module startup callback (from OAuthValidatorCallbacks).
 *
 * Initializes libcurl globals. This is called once when the
 * PostgreSQL backend starts.
 */
static void
validator_startup(ValidatorModuleState *s)
{
    const char *ver;
    (void) s; /* Unused */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ver = curl_version();
    if (kc_debug)
        elog(DEBUG1, "kc: validator_startup: libcurl=%s, timeout_ms=%d", ver ? ver : "unknown", kc_http_timeout_ms);
}

/**
 * @brief Module shutdown callback (from OAuthValidatorCallbacks).
 *
 * Cleans up libcurl globals. This is called once when the
 * PostgreSQL backend shuts down.
 */
static void
validator_shutdown(ValidatorModuleState *s)
{
    (void) s; /* Unused */
    curl_global_cleanup();
    if (kc_debug)
        elog(DEBUG1, "kc: validator_shutdown");
}

/**
 * @brief Static structure defining the callbacks for this validator module.
 *
 * This structure is passed back to PostgreSQL's OAuth framework.
 */
static const OAuthValidatorCallbacks KC = {
    .magic       = PG_OAUTH_VALIDATOR_MAGIC,
    .startup_cb  = validator_startup,
    .shutdown_cb = validator_shutdown,
    .validate_cb = validate_token,
};

/**
 * @brief PostgreSQL hook function (magic block).
 *
 * Called by the OAuth framework (libpq/oauth.h) to retrieve this
 * module's implementation of the validator callbacks.
 *
 * @return A const pointer to the static OAuthValidatorCallbacks struct.
 */
const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
    return &KC;
}

/**
 * @brief PostgreSQL module initialization function.
 *
 * This function is called when the module is loaded. It defines all the
 * GUC (Grand Unified Configuration) variables for this module and
 * reserves the "kc" prefix to avoid conflicts.
 *
 * All GUCs are marked with PGC_SIGHUP, meaning they can be reloaded
 * by sending a SIGHUP signal to the postmaster.
 */
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
        "Permission resource part (<resource>#<scope>)", NULL,
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

    DefineCustomBoolVariable( "kc.insecure",
        "Allow insecure certificates, such as, self-signed certificate. Must be used with caution.", NULL,
        &kc_insecure, false, PGC_SIGHUP, 0, NULL, NULL, NULL);

    /* Reserve the "kc." prefix to prevent conflicts */
    MarkGUCPrefixReserved("kc");
}
