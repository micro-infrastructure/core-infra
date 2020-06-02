const name = 'generic'


var isEmpty = function(obj) {
  return Object.keys(obj).length === 0;
}

function handler(details) {
	let cmd = ""
	if(details.config && details.config.mountStorageAdaptors) {
		details.privileged = true
		details.capabilities = ["SYS_ADMIN"]
		const m = details.config.dataPath || "/data"
		details.adaptors.map(a => {
			const host = a.env.filter(e => {
				return e.name == "NAME"
			})
			if (isEmpty(host)) return []
			return {
				host: host[0].value,
				port: a.ports[0].containerPort
			}
		}).forEach(a => {
			if (isEmpty(a)) return
			cmd += " echo $JWTUSERS | base64 -d > /assets/jwtusers && /bin/mkdir -p " + m + "/" + a.host + " && echo \'http://localhost:" + a.port + " u p\' >> /etc/davfs2/secrets && mount -t davfs http://localhost:" + a.port + " " + m + "/" + a.host + " && " 
		})

	}
	cmd += details.cmd[0]
	return {
				"name": details.name,
				"image": details.image,
				"imagePullPolicy": "Always",
				"ports": [
					{
						"containerPort": details.containerPort
					}
				],
				"env": details.env,
				"volumeMounts": details.volumes || [],
				"securityContext": {
					"privileged": details.privileged || false,
						"capabilities": {
							"add": details.capabilities || []
						}
				},
				"command": ["/bin/bash", "-c" ],
				"args": [cmd]
			}
}

module.exports = function(moduleHolder) {
	moduleHolder[name] = handler
	console.log("Loaded container module: " + name)
}

