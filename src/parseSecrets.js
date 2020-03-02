const YAML = require('yaml')
const fs = require('fs')
const path = require('path')
const cmdArgs = require('command-line-args')


const cmdOptions = [
	{ name: 'secretsFile', alias: 's', type: String},
	{ name: 'addFile', alias: 'a', type: String},
	{ name: 'display', alias: 'd', type: String},
	{ name: 'list', alias: 'l', type: Boolean}
]

function encodeBase64(s) {
	return new Buffer(s).toString('base64')
}

function decodeBase64(d) {
	if(!d) return null
	return new Buffer(d, 'base64').toString()
}

const options = cmdArgs(cmdOptions)
const secrets = fs.readFileSync(options.secretsFile, "utf-8")
const jsonSecrets = YAML.parse(secrets)
if (options.display) {
	const d = jsonSecrets.data[options.display]
	console.log(options.display + ": " + decodeBase64(d))
	return
}
if (options.list) {
	Object.keys(jsonSecrets.data).forEach(k => {
		console.log(k)
	})
	return
}
const dataToAdd = encodeBase64(fs.readFileSync(options.addFile, "utf-8"))
const fieldName = path.basename(options.addFile)

jsonSecrets.data[fieldName] = dataToAdd

console.log(YAML.stringify(jsonSecrets))
