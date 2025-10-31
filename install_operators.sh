kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.27/releases/cnpg-1.27.1.yaml
kubectl apply -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.2/kubernetes/keycloaks.k8s.keycloak.org-v1.yml
kubectl apply -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.2/kubernetes/keycloakrealmimports.k8s.keycloak.org-v1.yml
kubectl -n default apply -f https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/26.4.2/kubernetes/kubernetes.yml
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.1/cert-manager.yaml

