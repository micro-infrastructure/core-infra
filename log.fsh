#!/usr/bin/fish
set UC $argv[1]
if [ "$UC" ]
	echo $UC
else
	set UC 'process-core'
end
kubectl get pods -n $UC
kubectl logs -f (kubectl get pods -n $UC | grep core-infra | grep "Running" | awk '{print $1}') -n $UC -c web
