const name = 'lofar-download'

function encodeBase64(s) {
	return new Buffer(s).toString('base64')
}

function handler(details) {
	const user = {
		[[details.user.email]]: {
			'publicKey': encodeBase64(details.user.keys.raw.public)
		}
	}
	const image = details.image || "microinfrastructure/adaptor-lofar-download"
	const users = encodeBase64(JSON.stringify(user))

	const o = {
		"name": details.name,
		"image": image,
		"imagePullPolicy": "Always",
		"ports": [
			{ "containerPort": details.containerPort }
		],
		"env": [
			{ "name": "AMQP_HOST", "value": "127.0.0.1" },
			{ "name": "JWTUSERS", "value": users },
			{ "name": "PORT", "value": "" + details.containerPort + "" }
		],
		"volumeMounts": [
			{ "name": "ssh-key", "mountPath": "/ssh", "readOnly": true },
			{ "name": "shared-data", "mountPath": "/shared-data" }
		],
		"command": ["/bin/sh", "-c"],
		"args": ["sleep 15 && python3 src/__main__.py"]
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
