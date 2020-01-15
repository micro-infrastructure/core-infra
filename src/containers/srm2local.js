const name = 'srm2local'

function encodeBase64(s) {
	return new Buffer(s).toString('base64')
}

function handler(details) {
	const user = {
		[[details.user.email]]: {
			'publicKey': encodeBase64(details.user.keys.raw.public)
		}
	}
	const image = details.image || "microinfrastructure/adaptor-srm2local"
	const users = encodeBase64(JSON.stringify(user))

	const o = {
		"name": details.name,
		"image": image,
		"imagePullPolicy": "Always",
		"ports": [
			{
				"containerPort": details.containerPort
			}
		],
		"env": [
			{ "name": "AMQP_HOST", "value": "127.0.0.1" },
			{ "name": "JWTUSERS", "value": users },
			{ "name": "PORT", "value": details.containerPort }
		],
		"volumeMounts": [
			{ "name": "shared-data", "mountPath": "/shared-data" }
		],
		"command": ["/bin/sh", "-c"],
		"args": ["sleep 15 && python src/app.py"]
	}

	if (details.env) {
		for (let [name, value] of Object.entries(details.env)) {
			o.env.push({ name, value });
		}
	}

	return o
}

module.exports = function (moduleHolder) {
	moduleHolder[name] = handler
	console.log("Loaded container module: " + name)
}
