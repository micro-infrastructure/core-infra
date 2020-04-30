.PHONY: all

build:
	docker build -t recap/process-core-infra:v0.1 .

run: build
	docker run -it recap/process-core-infra:v0.1 /bin/sh

push: build
	docker push recap/process-core-infra

deploy: push
	kubectl delete -f core-infra.yaml 
	kubectl create -f core-infra.yaml
	kubectl get pods -n process-core

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
