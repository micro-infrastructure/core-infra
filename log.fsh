#!/usr/bin/fish
kubectl get pods -n process-core
kubectl logs -f (kubectl get pods -n process-core | grep core-infra | awk '{print $1}') -n process-core -c web
