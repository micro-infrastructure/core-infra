const name = 'rabbitmq'

function encodeBase64(s) {
	return new Buffer(s).toString('base64')
}

function handler(details) {
	const user = {
		[[details.user.email]]: {
			'publicKey': encodeBase64(details.user.keys.raw.public)
		}
	}
	const image = details.image || "rabbitmq:3"
	const users = encodeBase64(JSON.stringify(user))

	const o = {
		"name": details.name,
		"image": image,
		"imagePullPolicy": "Always",
		"ports": [
			{ "containerPort": details.containerPort || 5672 }
		],
		"env": [
			{ "name": "AMQP_HOST", "value": "127.0.0.1" },
			{ "name": "JWTUSERS", "value": users }
		],
		"volumeMounts": [
			{ "name": "shared-data", "mountPath": "/shared-data" }
		],
		"command": ["rabbitmq-server"],
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

