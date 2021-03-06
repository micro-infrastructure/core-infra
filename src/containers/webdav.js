const md5 = require('md5')
const name = 'webdav'
function handler(details) {

	const htpass = details.config.user + ":jsdav:" + md5(details.config.user + ":jsdav:" + details.config.pass)
	const env = []
	const vol = []
	env.push({ "name": "HTDIGEST", "value": htpass })
	vol.push({ "name": "shared-data", "mountPath": "/shared-data" })

	if(details.env) {
		if(!Array.isArray(details.env)) {
			// convert to array
			Object.keys(details.env).forEach(k => {
				env.push({
					name: k,
					value: details.env[k]
				})
			})
		} else {
			details.env.forEach(e => {
				env.push(e)
			})
		}
	}

	if(details.volumes) {
		details.volumes.forEach(v => {
			vol.push(v)
		})
	}

	let cmd = ""
	cmd += "echo $HTDIGEST > /assets/htusers && "
	if(!details.adaptors) details.adaptors = []
	if(details.config.mountStorageAdaptors) {
		details.adaptors.map(a => {
			const host = a.env.filter(e => {
				return e.name == "NAME"
			})
			return {
				host: host[0].value,
				port: a.ports[0].containerPort
			}
		}).forEach(a => {
			cmd += " echo $HTDIGEST > /assets/htusers && /bin/mkdir -p /data/" + a.host + " && echo \'http://localhost:" + a.port + " u p\' >> /etc/davfs2/secrets && mount -t davfs http://localhost:" + a.port + " /data/" + a.host + " && " 
		})
	}

	cmd += " cd /root/webdavserver && node webdavserver-ht.js -p " + details.containerPort
	return {
				"name": details.name,
				"image": "recap/process-webdav:v0.3",
				"imagePullPolicy": "Always",
				"ports": [
					{
						"containerPort": details.containerPort
					}
				],
				"env": env,
				"volumeMounts": vol,
				"securityContext": {
					"privileged": true,
						"capabilities": {
							"add": [ "SYS_ADMIN" ]
						}
				},
				"command": ["/bin/sh", "-c" ],
				"args": [cmd]
			}
}

module.exports = function(moduleHolder) {
	moduleHolder[name] = handler
	console.log("Loaded container module: " + name)
}

