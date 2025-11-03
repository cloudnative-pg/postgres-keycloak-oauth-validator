# Pilot demostration instructions 

## Required Tools

The following tools are required to perform the following demo:

* [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
* [KinD](https://kind.sigs.k8s.io/)

## How to follow the instructions

All the content of the files will be added step by step with an explanation of how they should
be used, they can be put in a file per example or in a long file separated by `---`, the
recommended way will be one per file, and at the end there will be one file to download and
cannot be posted since it's too long

The `kubectl` command all should be executed in the same namespace, by simplicity, we use the
`default` one which is the default after we create the KinD cluster.

## Setting up the KinD cluster

The demonstration can only be performed on Kubernetes 1.33.x or above, this due
to the ImageVolume feature that is required to mount the extension/module images
inside the pods.

### KinD configuration

Save the following configuration file as [kind-config.yaml](./kind-config.yaml) to set up your cluster:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
featureGates:
  # any feature gate can be enabled here with "Name": true
  # or disabled here with "Name": false
  # not all feature gates are tested, however
  "ImageVolume": true
```

Now create the cluster with the following command:

```bash
kind  create cluster --name pg-imagevolume --config=kind-config.yaml
```

### Install required operators

For our demonstration require the following operators:

* [CloudNativePG](https://cloudnative-pg.io/)
* [Keycloak](https://www.keycloak.org/guides#operator)
* [cert-manager](https://cert-manager.io/)

All of them can be installed with the following list of commands:

```bash
kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.27/releases/cnpg-1.27.1.yaml
kubectl apply -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.2/kubernetes/keycloaks.k8s.keycloak.org-v1.yml
kubectl apply -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.2/kubernetes/keycloakrealmimports.k8s.keycloak.org-v1.yml
kubectl -n default apply -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.2/kubernetes/kubernetes.yml
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.1/cert-manager.yaml
```
No is required to wait for a few minutes to have everything ready and working

### Deploying the required objects

We have now to deploy all the required objects to have a Keycloak service working properly

#### Deploying the database for Keycloak

Using CloudNativePG we can deploy the require PostgreSQL database to be used by Keycloak
with the following file:

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

The name of our database is `keycloak` and the name of the cluster `keycloak-db`, this will
be useful in the future.

#### Generating the certificates

The keycloak server will require to have certificates to serve the content overt HTTPS, which will
be required on the PostgreSQL side.

We create the issuer first:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: keycloak-issuer
spec:
  selfSigned: {}
```

Then we generate the certificate with the proper `dnsNames`, important to have `keycloak-app-service`
which is the default service and also `keycloak-app` that we create to have a simplified version of
the domain and for future testing.

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

#### Starting up the Keycloak server

Once we have the require database and certificates, we can now set up the Keycloak instance:

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

Some important points here are:

* The `tlsSecret` points to the secret with the certificates generate by cert-manager
* `db` section use the default secrets generated by CloudNativePG to allow Keycloak instance to access
   the database service
* To have a more flexible environment the `hostname.strict` is set to `false`, so we don't have to force
  only one specific domain for everything

We create our generic service to access from everywhere with a simplified name:

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

This will not be used the right away but later to create more base examples in the future or to access
the Keycloak instance from everywhere exposed with an Ingress

#### Testing the Keycloak service

By now, the Keycloak should be up, but it's important to check that the pod `keycloak-app-0` is up
and running.

We can now test the access to the interfaz, in one terminal we port-forward the interface:

```bash
kubectl port-forward services/keycloak-app-service 8443
```

And in another terminal we get the temporary admin password, that we will use during the whole demonstration

```bash
kubectl get secrets keycloak-app-initial-admin -ojsonpath='{.data.password}' | base64 -d
```

Now we can access the Keycloak server in our browser with the following URL:

```text
https://localhost:8443/admin/master/console/
```

It is important to notice that you will have to accept that it's a self-signed certificate.

Username: temp-admin
Password: (the one that w egot in the previous step)

Once we confirm that we can properly access the Keycloak instance, we proceed to load the Realm

#### Loading the Realm

For our demonstration we have a fixed realm with the name `demo` and a couple of pre-settings for
`Clients`, `scopes`, `policies` and `users`

The [kecloak-realm.yaml](./keycloak-realm.yaml) can be downloaded and applied in the following way:

```bash
kubectl apply -f keycloak-realm.yaml
```

This will create a `KeycloakRealmImport` that will connect to our Keycloak instance and pre-load
all the required settings using a Kubernetes Job that later can be deleted.

After the job is completed we can proceed, this can be check with the following command:

```bash 
kubectl get job realm-demo 
```

Once the Job is finished, verify that the realm `demo` was created in the interface


### Creating our CloudNativePG cluster with OAuth

We can now create the CloudNativePG cluster that will use Keycloak for the authentication and
authorization method.

First step is to create our initial SQL `ConfigMap` that will contain some examples to apply
the require roles and permissions:

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

This will generate a `ConfigMap` with the name `pg-init-sql` that will be used later.

Now we create the CloudNativePG cluster with the required configurations:

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
Some explanations to the file are required while the cluster is being created:

* `env`: This section contains a couple of required environment variables, the important ones are `PGAUTHDEBUG`
  that will allow us to use the next variable `PGAUTHCAFILE`, this will accept the self-signed certificate that
  we generated using the cert-manager
* `projectedVolumeTemplate`: Mount the generated certificate inside the container to be used by PostgreSQL instance
* `boostrap`: We require to have a `postInitApplicationSQLRefs` so we trigger the SQL after the database is created
* `postgresql.extensions`: This will mount the specified image inside the container and will make the `kc_validator`
  available to be loaded inside PostgreSQL
* `parameters`: The full section is related to the OAuth validation, first we load the `kc_validator` and then we
  configure it using the GUCs prefixed with `kc.`
* `pg_hba`: PostgreSQL will have to match the client OAuth requests, we set here how these request are going to be handled

### Testing our authentication

Now we can test the connection to our PostgreSQL instance using Keycloak for the OAuth part.

For simplicity we create a pod inside the same namespace so we can always access everything from the same network:

```bash
kubectl run debian --image=debian:unstable -- sleep 100000
```

It is important to use `unstable` since this will contain the PostgreSQL version 18, which is the one that implements
the OAuth feature.

Now we get into the pod:

```bash
kubectl exec -ti debian -- bash
```

And we trigger the following command:

```bash
apt update && apt dist-upgrade -y && apt install -y postgresql-client libpq-oauth
```

The commands will install `psql` and the required lib to support libpq-oauth

In another terminal we now need to get the CA for the certificates we generated for Keycloak, otherwise, we will not
be able to verify the certificates

```bash
kubectl get secrets keycloak-certificate -ojsonpath='{.data.ca\.crt}' | base64 -d
```

We need now to place the content in a file inside the `debian` pod, for that we can just use `/root/ca.crt`

```bash 
echo "<content....>" > /root/ca.crt
```

Let's trigger our first login:

```bash
PGOAUTHDEBUG=UNSAFE PGOAUTHCAFILE=/root/ca.crt psql "host=pg-oauth-rw user=app_readonly dbname=appdb oauth_issuer=https://keycloak-app-service:8443/realms/demo oauth_client_id=appA oauth_client_secret=XyIXBUgsLhgvJJO4EQrcp8iJvHqaJIjm oauth_scope='db_access'"
```

This will offer a URL that needs to be open in your browser, for this the `port-forward` that expose Keycloak needs
to be running.

The requested data needs to be set.

Username: peggie
Password: 123123

After the authorization has been done, your `psql` command should be already logged in.

