const name = 'generic'
function handler(details) {
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
				"args": details.cmd
			}
}

module.exports = function(moduleHolder) {
	moduleHolder[name] = handler
	console.log("Loaded container module: " + name)
}

