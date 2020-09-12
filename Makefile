.PHONY: all

build:
	docker build -t microinfrastructure/process-core-infra:v0.2 .

run: build
	docker run -it microinfrastructure/process-core-infra:v0.2 /bin/sh

push: build
	docker push microinfrastructure/process-core-infra

deploy: 
	kubectl delete -f core-infra.yaml 
	kubectl create -f core-infra.yaml
	kubectl get pods -n process-core

watch: 
	watch "kubectl get pods -n process-core"

deploy-dev: push
	kubectl delete -f core-infra-dev.yaml 
	kubectl create -f core-infra-dev.yaml
	kubectl get pods -n process-core-dev

create-dev-ns:
	kubectl create ns process-core-dev
	kubectl get secret vault -n process-core --export -o yaml | kubectl apply -n process-core-dev -f -

log:
	./log.fsh process-core

log-dev:
	./log.fsh process-core-dev
