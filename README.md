[![CloudNativePG](./logo/cloudnativepg.png)](https://cloudnative-pg.io/)

# PostgreSQL OAuth Validator for Keycloak

**EXPERIMENTAL**

**Requires**: PostgreSQL 18+

This module enables PostgreSQL 18 to delegate authorization decisions to Keycloak using OAuth tokens, leveraging Keycloak Authorization Services for fine-grained, token-based access control.
It sends a permission request to Keycloak's token endpoint using `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket` and expects a decision response (`response_mode=decision`), which is a Keycloak-specific extension.
It is designed for use with CloudNativePG, allowing database role elevation to be controlled by Keycloak policies.

---

## Features

- **Keycloak-based authorization for PostgreSQL roles**
  - Delegates database role elevation decisions to Keycloak Authorization Services using OAuth tokens.
- **Permission string construction**
  - Builds permission strings as `<resource_name>#<scope>` and sends permission requests to Keycloak's token endpoint (`grant_type=urn:ietf:params:oauth:grant-type:uma-ticket`, `response_mode=decision`).
- **Configurable via PostgreSQL GUC parameters**
  - All integration settings (endpoints, resource names, timeouts, debug, etc.) are controlled via GUCs.
- **Secure HTTP communication**
  - Uses libcurl for HTTP requests with configurable timeouts and safe logging.
- **Optional JWT issuer verification**
  - Can verify the `iss` claim in JWT tokens for additional security.

---

## Example: CloudNativePG Configuration

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: pg-oauth
spec:
  imageName: pg18-kc-validator:18.0      # Image containing kc_validator.so
  instances: 1

  postgresql:
    parameters:
      oauth_validator_libraries: "kc_validator"
      kc.token_endpoint: "https://<keycloak>/realms/<realm>/protocol/openid-connect/token"
      kc.audience: "postgres-resource"
      kc.resource_name: "appdb"       # Resource name in Keycloak
      kc.client_id: "postgres-resource"
      kc.http_timeout_ms: "2000"
      kc.expected_issuer: "https://<keycloak>/realms/<realm>"
      kc.debug: "on"
      kc.log_body: "on"
      log_min_messages: "debug1"
    pg_hba:
      - host all all 0.0.0.0/0 oauth issuer="https://<keycloak>/realms/<realm>" scope=db_access validator="kc_validator" delegate_ident_mapping=1
```

For a full example, see `examples/cnpg/cluster.yaml`.

---

## Keycloak Configuration Steps

1. **Realm**
   Create or use an existing realm (e.g., `demo`).

2. **Resource Server Client** (`kc.audience`)
   Create a client for Authorization Services (e.g., `postgres-resource`).
   Enable Authorization Services and add scopes as needed (e.g., `app_readonly`, `app_readwrite`).

3. **Validator Client** (`kc.client_id`)
   A client allowed to call the token endpoint for permission decisions.

4. **Resource & Permission**
   Resource name: `<kc.resource_name>` (e.g., `appdb`).
   Scope name: `<scope>` (e.g., `app_readonly`, `app_readwrite`).
   Permission name: `<resource_name>#<scope>` (e.g., `appdb#app_readonly`).
   Create a permission for each database role you want to allow (e.g., DB role `app_readonly` maps to Keycloak scope `app_readonly`, permission name `appdb#app_readonly`).

5. **Policies**
   Attach policies to permissions so that only intended users can access specific scopes.

6. **Issuer Verification (optional)**
   Set `kc.expected_issuer` to your realm's issuer URL (e.g., `https://<keycloak>/realms/<realm>`).

---

## Quick Start with psql and Device Flow

You can quickly test the validator using Keycloak's Device Flow and psql:

1. **Connect to PostgreSQL using psql with OAuth parameters:**

    ```bash
    psql "host=<keycloak> \
        user=app_readonly \
        dbname=appdb \
        oauth_issuer=https://<keycloak>/realms/demo \
        oauth_client_id=appA \
        oauth_client_secret=<client secret> \
        oauth_scope='db_access'"
    ```

    When you run this command, psql will display a Device Authorization URL and a device code.

2. **Authenticate via browser:**

    - Open the displayed URL in your browser.
    - Enter the device code shown by psql.
    - Log in with your Keycloak username and password.

    Once authentication is complete, psql will automatically obtain an access token and connect to the database.

> Note:
The DB role (`app_readonly`) should match the Keycloak scope name.
The validator will request permission `<resource_name>#<scope>` (e.g., `appdb#app_readonly`) from Keycloak Authorization Services.

---

## Build Instructions

### Local

To compile the extension is required [meson](https://mesonbuild.com/) tool.

```bash
meson setup build
meson compile -C build
```
The extension will be located inside the `build/` directory, that was
created during the setup process.

### Docker

```bash
docker build -t pg-kc-validator -f docker/Dockerfile .
```

---

## Security Notes

- Do not use self-signed certificates (server.crt) in production; always use a trusted CA.
- Enable `kc.log_body` only for debugging; keep it `off` in production.
- Place CA certificates in `/usr/local/share/ca-certificates/` and run `update-ca-certificates` in your Docker image.

---

## License

Apache-2.0. See `LICENSE`.

---
