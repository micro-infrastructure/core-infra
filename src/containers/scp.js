const name = 'scp'
function encodeBase64(s) {
	return new Buffer(s).toString('base64')
}
function handler(details) {
	const user = {
		[[details.user.email]]: {
			'publicKey': encodeBase64(details.user.keys.raw.public)
		}
	}
	const users = encodeBase64(JSON.stringify(user))
	const env = []
	env.push({ "name": "NAME", "value": details.name })
	env.push({ "name": "JWTUSERS", "value": users })
	if(details.env) {
		details.env.forEach(e => {
			env.push(e) 
		})
	}
	let cmd = "sleep 15 && echo $JWTUSERS | base64 -d > /assets/jwtusers.json"
	cmd += " && echo $INFRA | base64 -d > /assets/infra.json"
	cmd += " && echo $NETWORK | base64 -d > /assets/network.json"
	cmd += " &&  /bin/cat /ssh/id_rsa > /root/.ssh/id_rsa && /bin/cat /ssh/id_rsa.pub > /root/.ssh/id_rsa.pub  && /bin/chmod 600 /root/.ssh/id_rsa && cd /root/app && node app.js --sshPrivateKey /root/.ssh/id_rsa -u /assets/jwtusers.json -p " + details.containerPort + " "

	return {
				"name": details.name,
				"image": "microinfrastructure/service-copy:v0.2",
				"imagePullPolicy": "Always",
				"ports": [
					{
						"containerPort": details.containerPort
					}
				],
				"env": env,
				"volumeMounts": [
					{ "name": "ssh-key", "mountPath": "/ssh", "readOnly": true },
					{ "name": "shared-data", "mountPath": "/shared-data" }
				],
				"command": ["/bin/sh", "-c" ],
				"args": [cmd]
			}
}


module.exports = function(moduleHolder) {
	moduleHolder[name] = handler
	console.log("Loaded container module: " + name)
}

