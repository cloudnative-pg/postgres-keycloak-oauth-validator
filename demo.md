# Pilot Demonstration Instructions

## Required Tools

The following tools are required to perform this demo:

* [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
* [KinD](https://kind.sigs.k8s.io/)

## How to follow these instructions

All the content of the YAML files will be displayed in each step, and can be applied with the related
`kubectl` command, except for the KinD configuration. The `kubectl` commands should be executed in
the same namespace. For simplicity, this demo uses the `default` namespace in the following instructions.
You will find the same YAML files inside the `demo/` directory for inspection and/or to use them.

## Set up the local kubernetes cluster

The demonstration can only be performed on Kubernetes 1.33.x or above, this due
to the `ImageVolume` feature that is required to mount the extension/module images
inside the pods. Image volumes are enabled by default starting with Kubernetes 1.35.

### KinD configuration (for Kubernetes 1.33 and 1.34)

If you are using Kubernetes 1.33 or 1.34 with Kind, you need the
[kind-config.yaml](./demo/kind-config.yaml) file, which serves as the
configuration to set up the local Kubernetes cluster with the required feature
to run this demo.

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
  # any feature gate can be enabled here with "Name": true
  # or disabled here with "Name": false
  # not all feature gates are tested, however
  "ImageVolume": true
```

### Start KinD

Create the cluster with the following command:

```bash
kind  create cluster --name pg-imagevolume
```

For Kubernetes 1.33 or 1.34:

```bash
kind  create cluster --name pg-imagevolume --config=./demo/kind-config.yaml
```


## Install required operators

This demonstration requires the following operators:

* [CloudNativePG](https://cloudnative-pg.io/)
* [Keycloak](https://www.keycloak.org/guides#operator)
* [cert-manager](https://cert-manager.io/)

All of them can be installed with the following list of commands:

```bash
kubectl apply --server-side \
  -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.28/releases/cnpg-1.28.0.yaml
kubectl apply \
  -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.5.1/kubernetes/keycloaks.k8s.keycloak.org-v1.yml
kubectl apply \
  -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.5.1/kubernetes/keycloakrealmimports.k8s.keycloak.org-v1.yml
kubectl apply \
  -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.5.1/kubernetes/kubernetes.yml
kubectl apply \
  -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
```

> [!NOTE]
> The `-n default` parameter is omitted in each of the above commands, as it is
> the default namespace of the KinD cluster.

Note: it is required to wait for a few minutes to make sure everything up and running. You can check and monitor
these resources with the following command:

```bash
kubectl get pods -Aw
```

## Deploying the required objects

Deploy all the required objects to set up a working Keycloak service.

### Deploying the database for Keycloak

Using CloudNativePG deploy the required PostgreSQL database to be used by Keycloak with the following file:

```bash
kubectl apply -f ./demo/keycloak-db.yaml
```

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
spec:
  instances: 3
  bootstrap:
    initdb:
      database: keycloak
      owner: keycloak
  storage:
    size: 1Gi
```

The name of our database is `keycloak`, and the name of the cluster `keycloak-db`. This information will
be useful in future steps.

### Deploy the certificate issuer

The keycloak server will require certificates to serve the content over HTTPS, which will
be used by PostgreSQL.

First create the issuer:

```bash
kubectl apply -f ./demo/certificates-issuer.yaml
```

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: keycloak-issuer
spec:
  selfSigned: {}
```

### Generate the certificates

Then generate the certificate with the following `dnsNames`:

* `keycloak-app-service` - which is the default service
* `keycloak-app-service.svc.cluster.local` - default service with FQDN
* `keycloak-app` - a simplified version of the domain for future testing

```bash
kubectl apply -f ./demo/keycloak-certificates.yaml
```

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: keycloak-certificate
spec:
  dnsNames:
    - keycloak-app-service
    - keycloak-app-service.svc.cluster.local
    - keycloak-app
  subject:
    countries:
      - IT
    localities:
      - Prato
    organizations:
      - cert-manager
  duration: 2160h0m0s
  issuerRef:
    kind: ClusterIssuer
    name: keycloak-issuer
  privateKey:
    algorithm: RSA
    encoding: PKCS1
    rotationPolicy: Always
  secretName: keycloak-certificate
```

## Deploy the Keycloak server

Once you have the required database and certificates, you can set up the Keycloak instance.

### Starting up the Keycloak server

Deploy the Keycloak server, named `keycloak-app`:

```bash
kubectl apply -f ./demo/keycloak-server.yaml
```

```yaml
apiVersion: k8s.keycloak.org/v2alpha1
kind: Keycloak
metadata:
  name: keycloak-app
spec:
  instances: 1
  db:
    vendor: postgres
    host: keycloak-db-rw
    usernameSecret:
      name: keycloak-db-app
      key: username
    passwordSecret:
      name: keycloak-db-app
      key: password
  additionalOptions:
    - name: log-console-output
      value: json
    - name: metrics-enabled
      value: 'true'
  http:
    tlsSecret: keycloak-certificate
  hostname:
    strict: false
  proxy:
    headers: xforwarded # double check your reverse proxy sets and overwrites the X-Forwarded-* headers
```

Some important points:

* the `tlsSecret` points to the secret with the certificates generated by cert-manager
* the `db` section uses the default secrets generated by CloudNativePG to allow Keycloak instance to access
   the database service
* to have a more flexible environment the `hostname.strict` is set to `false`, to not enforce only one specific
  domain for everything

### Create the service

Create a generic service to access from everywhere with a simplified name:

```bash
kubectl apply -f ./demo/keycloak-service.yaml
```

```yaml
apiVersion: v1
kind: Service
metadata:
  labels:
    app: keycloak
    app.kubernetes.io/instance: keycloak-app
    app.kubernetes.io/managed-by: keycloak-operator
  name: keycloak-app
spec:
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: 8443
  selector:
    app: keycloak
    app.kubernetes.io/instance: keycloak-app
    app.kubernetes.io/managed-by: keycloak-operator
  type: ClusterIP
```

Note: this will not be used right away, but later. It serves to create more base examples in the future or to access
the Keycloak instance from everywhere exposed with an Ingress.

### Testing the Keycloak service

Check for the `keycloak-app-0` pod to be up and running:

```bash
kubectl get pod keycloak-app-0
```

Enable the port forwarding with:

```bash
kubectl port-forward services/keycloak-app-service 8443
```

And in another terminal get the temporary admin password, that will be used during the whole demonstration:

```bash
kubectl get secrets keycloak-app-initial-admin -ojsonpath='{.data.password}' | base64 -d
```

Now access the Keycloak server in your browser from the following URL:

```text
https://localhost:8443/admin/master/console/
```

Note: You will have to accept that it's a self-signed certificate in your browser.

* Username: temp-admin
* Password: (the one from the previous step)

Once you verified the Keycloak interface is accessible, you can proceed.

### Loading the Realm

In this demonstration we choose a fixed realm with the name `demo` and a couple of pre-settings for
`Clients`, `scopes`, `policies` and `users`.

The [kecloak-realm.yaml](./demo/keycloak-realm.yaml) can be downloaded and applied in the following way:

```bash
kubectl apply -f ./demo/keycloak-realm.yaml
```

This will create a `KeycloakRealmImport` that will connect to our Keycloak instance and load
all the required settings. This procedure will create a Kubernetes Job that can be deleted once
completed.

Check for the job completion with:

```bash 
kubectl get job realm-demo 
```

Once the Job is in `Completed` state, verify that the realm `demo` was created from the web interface.

## Deploy PostgreSQL

Now it's time to create the CloudNativePG cluster that will use Keycloak for the authentication and
authorization method.

### Create the example data with SQL

First create the initial SQL `ConfigMap` called `pg-init-sql` that contains some examples of the required
roles and permissions:

```bash
kubectl apply -f ./demo/init_sql-configmap.yaml
```

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pg-init-sql
data:
  init.sql: |
    -- Create the 'users' table
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Create the 'orders' table
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      product VARCHAR(100),
      amount INTEGER,
      ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Insert sample users
    INSERT INTO users (username, email) VALUES
      ('alice', 'alice@example.com'),
      ('bob', 'bob@example.com');

    -- Insert sample orders
    INSERT INTO orders (user_id, product, amount) VALUES
      (1, 'Widget', 3),
      (2, 'Gadget', 5);

    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_readonly') THEN
        CREATE ROLE app_readonly LOGIN;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_readwrite') THEN
        CREATE ROLE app_readwrite LOGIN;
      END IF;
    END$$;

    REVOKE CONNECT ON DATABASE appdb FROM PUBLIC;
    GRANT  CONNECT ON DATABASE appdb TO app_readonly, app_readwrite;

    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    GRANT  USAGE ON SCHEMA public TO app_readonly, app_readwrite;
    GRANT  CREATE ON SCHEMA public TO app_readwrite;

    GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readwrite;
    GRANT INSERT ON ALL TABLES IN SCHEMA public TO app_readwrite;

    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_readonly;
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO app_readwrite;

    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT SELECT ON TABLES TO app_readonly;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT USAGE, SELECT ON SEQUENCES TO app_readonly;

    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT SELECT, INSERT ON TABLES TO app_readwrite;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO app_readwrite;
```

### Creating the CloudNativePG cluster with OAuth

Create the CloudNativePG cluster with the required configurations:

```bash
kubectl apply -f ./demo/pg_oauth-db.yaml
```

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: pg-oauth
  annotations:
    cnpg.io/validation: disabled
spec:
  instances: 3
  #logLevel: debug

  env:
  - name: "PGOAUTHDEBUG"
    value: "UNSAFE"
  - name: "SSL_CERT_DIR"
    value: "/projected/certificate/"
  - name: "CURL_CA_BUNDLE"
    value: "/projected/certificate/ca.crt"
  - name: "PGOAUTHCAFILE"
    value: "/projected/certificate/ca.crt"
  # Bootstrap from scratch and run our init SQL from a ConfigMap
  bootstrap:
    initdb:
      database: appdb
      owner: app
      postInitApplicationSQLRefs:
        configMapRefs:
          - name: pg-init-sql
            key: init.sql

  projectedVolumeTemplate:
    sources:
      - secret:
          name: keycloak-certificate
          items:
            - key: ca.crt
              path: certificate/ca.crt
            - key: tls.crt
              path: certificate/tls.crt

  managed:
    roles:
      - name: app_readonly
        ensure: present
        comment: readonly user
        login: true
      - name: app_readwrite
        ensure: present
        comment: readwrite user
        login: true

  storage:
    size: 1Gi
  postgresql:
    extensions:
    - name: kc-validator
      image:
        reference: ghcr.io/cloudnative-pg/postgres-keycloak-oauth-validator-testing:18-dev-trixie
        pullPolicy: Always
      ld_library_path:
        - system
    parameters:
      oauth_validator_libraries: "kc_validator"

      kc.token_endpoint: "https://keycloak-app-service:8443/realms/demo/protocol/openid-connect/token"
      kc.audience:       "postgres-resource"
      kc.resource_name:  "appdb"
      kc.client_id:      "postgres-resource"
      kc.http_timeout_ms: "2000"
      #kc.expected_issuer: "https://keycloak-app/realms/demo"
      kc.debug: "true"
      kc.log_body: "on"
      log_min_messages: "debug1"

    pg_hba:
      - host all all 0.0.0.0/0 oauth issuer="https://keycloak-app-service:8443/realms/demo" scope=db_access validator="kc_validator" delegate_ident_mapping=1
```

Where:

* `env`: contains the required environment variables
  * `PGAUTHDEBUG`: allows you to use the next variable
  * `PGAUTHCAFILE`: accepts the self-signed certificate generated using the cert-manager
  * `SSL_CERT_DIR`: is the directory path containing the certificates
  * `CURL_CA_BUNDLE`: is the path to the actual CA bundle
* `projectedVolumeTemplate`: mounts the generated certificate inside the container as a projected volume
* `boostrap`: is required to execute the initial SQL commands
  * `postInitApplicationSQLRefs`: specifies the reference to retrieve the actual SQL configmap created in
    the previous step
* `postgresql.extensions`: mounts the specified image inside the container and to make the `kc_validator`
  extension available to be loaded inside PostgreSQL
* `parameters`: contains the full section of the PostgreSQL GUC related to the OAuth validation.
  * `oauth_validator_libraries`: loads the `kc_validator` to configure it using the GUCs prefixed with `kc.`
* `pg_hba`: contains the HBA entry to match the client OAuth requests and how these request are handled

## Testing authentication

Let's test the connection to our PostgreSQL instance using Keycloak for the OAuth part.

### Create a POD to access PostgreSQL from

For simplicity, create a pod inside the same namespace to access everything from the same network:

```bash
kubectl run debian --image=debian:unstable -- sleep 100000
```

Note: it is important to use the `unstable` release since it contains the PostgreSQL version 18. The previous versions
do not support the OAuth feature.

Get into the pod:

```bash
kubectl exec -ti debian -- bash
```

Trigger the following command:

```text
apt update && apt dist-upgrade -y && apt install -y postgresql-client libpq-oauth
```

These commands will install `psql` and the required libraries to support libpq-oauth.

From another terminal, get the CA for the certificates previously generated for Keycloak, otherwise, you will not
be able to verify the certificates:

```bash
kubectl get secrets keycloak-certificate -ojsonpath='{.data.ca\.crt}' | base64 -d
```

Place the content in a file inside the `debian` pod:

```text 
echo "<content....>" > /root/ca.crt
```

### Testing connection

Try the first login:

```text
PGOAUTHDEBUG=UNSAFE PGOAUTHCAFILE=/root/ca.crt psql "host=pg-oauth-rw user=app_readonly dbname=appdb oauth_issuer=https://keycloak-app-service:8443/realms/demo oauth_client_id=appA oauth_client_secret=XyIXBUgsLhgvJJO4EQrcp8iJvHqaJIjm oauth_scope='db_access'"
```

This will offer a URL that needs to be open in your browser, but **first you need to replace** the shown domain
with `localhost`. This requires the `port-forward` command to still be running to expose the Keycloak service.

Enter the requested data:

* Username: peggie
* Password: 123123

Once the authorization is done, your `psql` command should be already logged in.
