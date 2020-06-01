const YAML = require('yaml')
const cmdArgs = require('command-line-args')
const express = require('express')
const crypto = require('crypto')
const app = express()
const http = require('http')
const https = require('https')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const randomstring = require('randomstring')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const k8s = require('k8s')
const ssh = require('ssh2').Client
const keypair = require('keypair')
const forge = require('node-forge')
const path_module = require('path');
const rp = require('request-promise');
const promiseRetry = require('promise-retry');
const PersistentObject = require('persistent-cache-object');
const moduleHolder = {};
mongoose.set('useFindAndModify', false);

const VERSION = "0.2.1"

const cmdOptions = [
	{ name: 'mongo', alias: 'm', type: String},
	{ name: 'privateKey', alias: 'k', type: String},
	{ name: 'publicKey', alias: 'c', type: String},
	{ name: 'cert', alias: 's', type: String},
	{ name: 'port', alias: 'p', type: Number},
	{ name: 'dbpass', type: String},
	{ name: 'noDeploy', type: Boolean},
	{ name: 'host', alias: 'h', type: String},
    { name: 'config', type: String}
]

const options = cmdArgs(cmdOptions)
const config = (options.config) ? require(options.config) : require('./core-infra-config');


if(!config.entryEndpoints) {
	config.entryEndpoints = [ options.host, "sne-dtn-03.vlan7.uvalight.net"]
}

// load keys
const privateKey = fs.readFileSync(options.privateKey, "utf-8")
const publicKey = fs.readFileSync(options.publicKey, "utf-8")
const cert = fs.readFileSync(options.cert, "utf-8")
const credentials = {
	key: privateKey,
	cert: cert
}
const httpsServer = https.createServer(credentials, app)
const httpServer = http.createServer(app)

app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())
app.use(express.static('./'))
app.get('/', function(req, res,next) {
    res.sendFile(__dirname + '/index.html')
})

const api = '/api/v1'

// check mongo
const url = "mongodb://core-infra:" + options.dbpass + "@" + options.mongo + ":27017/process"
mongoose.connect(url)
const db = mongoose.connection
db.on('error', console.error.bind(console, "conn error"))
db.once('open', () => {
	console.log("[INFO] mongodb ok");
})

// check k8s
const kubeapi = k8s.api({
	endpoint: 'http://127.0.0.1:8080',
	version: '/api/v1'
})

const kubeext = k8s.api({
	endpoint: 'http://127.0.0.1:8080',
	version: '/apis/apps/v1'
})

const nodes = {}
const infras = new PersistentObject('./infras.db');
const deploymentDb = new PersistentObject('./deployments.db');

kubeapi.get('namespaces/process-core/pods', (err, data) => {
	if (err) throw err
	data.items.forEach(d => {
		console.log("[INFO]	namespace: process-core, pod: " + d.metadata.name);
	})
})

function md5sum(s) {
	const hash = crypto.createHash('md5').update(s).digest('hex');
	return hash;
}

function waitForNodeUp(name) {
	console.log("[INFO] waiting for node " + name + " to come up.")
	return new Promise((resolve, reject) => {
		const interval = setInterval(() => {
			kubeapi.get('nodes', (err, data) => {
				if(err) return
				const nodes = data.items.filter(d => {
					nodeName = d.metadata.name
					let up = false
					d.status.conditions.forEach(c => {
						if(c.type === 'Ready') {
							up = true
						}
					})
					if(up) {
						return nodeName
					}
				}).map(d => {
					return d.metadata.name
				}).filter(n => {
					if(n.indexOf(name) > -1) return n
				})
				if(!isEmpty(nodes)) {
					clearInterval(interval)
					resolve(nodes)
				}
			})
		}, 10000)

	})
}

async function removeNode(id) {
	const nodes = await updateAndCleanNodes(id)
	const filteredNodes = Object.keys(nodes).filter(n => {
		if(n.indexOf(id) > -1) return n
	})
	if(filteredNodes.length > 1) {
		console.log("[WARNING] not removing nodes due to multiple matches for " + id + " " + filteredNodes)
		return
	}
	if(!isEmpty(filteredNodes)) {
		setTimeout(() => {
			removeNode(id)
		}, 5000)
	}
}

function updateAndCleanNodes(id) {
	return new Promise((resolve,reject) => {
		kubeapi.get('nodes', (err, data) => {
		if (err) reject(err)
		data.items.forEach(d => {
			nodeName = d.metadata.name
			if(!nodes[d.metadata.name])
				nodes[d.metadata.name] = {}
			d.status.conditions.forEach(c => {
				if(c.type === 'Ready') {
					nodes[d.metadata.name]['status'] = c.status
					if(c.status === 'Unknown') {
						if(id) {
							if(!(nodeName.indexOf(id) > -1)) {
									return
							}
						}
						// remove node from k8s
						console.log("[INFO] removing node: " + nodeName)
						delete nodes[nodeName]
						kubeapi.delete('nodes/' + nodeName, (err, res) => {
							if(err) {
								console.log('[ERROR] error removing node: ', err)
								return
							}
						})
					} else {
						console.log("[INFO] found k8s node: " + nodeName + ", status " + c.status);
					}
				}
			})
		})
		resolve(nodes)
	})
	})
}

updateAndCleanNodes().then(n => {})

const cloudifyDeployments = {}

function loadModules(path) {
    fs.lstat(path, function(err, stat) {
        if (stat.isDirectory()) {
            // we have a directory: do a tree walk
            fs.readdir(path, function(err, files) {
                var f, l = files.length;
                for (var i = 0; i < l; i++) {
                    f = path_module.join('./', path, files[i]);
                    loadModules(f);
                }
            });
        } else {
			if(path_module.extname(path) != '.js') return
            // we have a file: load it
            require('./' + path)(moduleHolder);
        }
    });
}

function watchModules(path) {
	fs.watch(path, (event, who) => {
		if (event != 'change') return
		f = path + '/' + who
		loadModules(f)
	})
}

function encodeBase64(s) {
	return new Buffer(s).toString('base64')
}

function decodeBase64(d) {
	return new Buffer(d, 'base64').toString()
}

function createNamespace(name) {
	return {
	  "kind": "Namespace",
	  "apiVersion": "v1",
	  "metadata": {
		"name": name,
		"labels": {
		  "name": name
		}
	  }
	}
}

function createSecret(keys) {
	return {
	  "kind": "Secret",
	  "apiVersion": "v1",
	  "metadata": {
		  "name": "keys"
	  },
	  "type": "Opaque",
	  "data": {
		  "id_rsa": encodeBase64(keys.ssh.private),
		  "id_rsa.pub": encodeBase64(keys.ssh.public)
	  }
	}
}

function createVolumeClaim(details) {
	return {
		"kind": "PersistentVolumeClaim",
		"apiVersion": "v1",
		"metadata": {
			"name": details.name,
			"namespace": details.namespace,
			"labels": {
				"app": details.cntName
			}
		},
		"spec": {
			"storageClassName": "rook-ceph-block",
			"accessModes": [ 
				'ReadWriteOnce'
			],
			"resources": {
				"requests": {
					"storage": details.size
				}
			}
		}
	}
}

function isEmpty(a) {
	return (!Array.isArray(a) || !a.length) 
}

function createVolume(details) {
	if(!details) {
		// return default pod volumes
		return  [
		  {
			"name": "ssh-key",
			"secret": {
			  "secretName": "keys"
			}
		  },
		  {
			"name": "shared-data",
			"emptyDir": {}
		  }
		]
	}
}

function createDeployment(details, volumes, containers, initContainers) {
	const nodeSelector = (!isEmpty(details.deployNodes)) ? { 'kubernetes.io/hostname': details.deployNodes[0] }  : null
	return {
		kind: "Deployment",
		apiVersion: "apps/v1",
		metadata: {
			name: details.name,
			namespace: details.namespace,
			labels: {
				name: details.name
			}
		},
		spec: {
			selector: {
				  matchLabels: {
					app: details.name
				  }
				},
				template: {
				  metadata: {
					labels: {
					  app: details.name
					}
				  },
				  spec: {
					nodeSelector: {
						location: details.location,
					},
					hostname: details.name,
					volumes: volumes,
					nodeSelector: nodeSelector,
					containers: containers,
					initContainers: initContainers
				  }
				}
		}
	}
}

function createService(details) {
	const ns = details.namespace
	const uc = details.staticPorts
	const serviceName = details.iname + "-" + details.name

	const svc = {
		kind: "Service",
		apiVersion: "v1",
		metadata: {
			name: serviceName,
			namespace: details.namespace,
			labels: {
				app: details.iname,
				type: details.type
			}
		},
		spec: {
			selector: {
				app: details.iname
			},
			ports: [
				{
					port: details.targetPort,
					targetPort: details.targetPort
				}
			],
			type: "NodePort"
		}
	}

	if(uc) {
		svc.spec.ports[0]['nodePort'] = uc[details.name]
	}

	return svc
}

function generateToken(user, namespace) {
	return jwt.sign({
		user: user,
		namespace: namespace || "default",
		date: new Date().toISOString()
	}, privateKey, {algorithm: 'RS256'})
}

function checkToken(req, res, next) {
	if (req.user) {
		next()
		return
	}
	const token = req.headers['x-access-token']
	if (!token) {
		res.status(403).send()
		return
	}
	jwt.verify(token, publicKey, {algorithms: ['RS256']}, (err, decoded) => {
		if (err) {
			res.status(403).send()
			return
		}
		User.find({email: decoded.user}, (err, results) => {
			if (err) throw err
			if (isEmpty(results)) {
				res.status(403).send()
				return
			}
			const u = results[0]
			if(!u.keys.ssh.idFile) {
				u.keys = updateKeys(u.keys)
			}
			req['user'] = u
			next()
		})
	})
}

function checkAdminToken(req, res, next) {
	const token = req.headers['x-access-token']
	if (!token) {
		res.status(403).send()
		return
	}
	jwt.verify(token, publicKey, {algorithms: ['RS256']}, (err, decoded) => {
		if (err) {
			res.status(403).send()
			return
		}
		//console.log(decoded)
		if (!(decoded.user == 'admin')) {
			res.status(403).send()
			return
		}
		req['user'] = decoded.user
		next()
	})
}

app.get(api + '/test', [checkAdminToken, checkToken], async (req, res) => {
	res.status(200).send(req.user)
})

function deleteAndCreateSecret(namespace, data, name) {
		return new Promise((resolve, reject) => {
			const sName = name || 'keys'
			kubeapi.delete('namespaces/' + namespace + '/secrets/' + sName, (err) => {
				if (err) {
					if (!(err.reason == 'NotFound')) {
						console.log("[ERROR] error with creating secret: ", err)
					}
				}
				kubeapi.post('namespaces/' + namespace + '/secrets', createSecret(data), (err, result) => {
					if (err) reject()
					resolve(result)
				})
			})
		})
}

app.get(api + '/version', (req, res) => {
	res.status(200).send({
		version: VERSION
	})
})


app.put(api + '/user', checkAdminToken, async(req, res) => {
	
	const user = req.body

	User.find({email: user.email}, async(err, results) => {
		if (err) {
			res.status(500).send()
			throw err
		}
		try {
			// generate user token
			const userToken = generateToken(user.email, user.namespace)
			let keys = null
			if (results.length === 0) {
				const iuser = user.email.split('@')[0]
				// generate user keys
				keys = await generateKeys({
					email: user.email,
					user: iuser
				})
				//console.log(keys)
				// create user mongo entry
				new User({
					email: user.email,
					namespace: user.namespace,
					keys: keys,
					folders: user.folders,
					staticPorts: user.staticPorts,
					credentials: user.credentials
				}).save()
				console.log("[INFO] created new user: ", user.email)
			} else {
				const doc = results[0]
				const newFolders = updateFolders(doc.folders || [], user.folders || [])
				const newPorts = updateDict(doc.staticPorts || {}, user.staticPorts || {})
				const newCredentials = updateDict(doc.credentials || {}, user.credentials || {})
				const updatedKeys = updateKeys(doc.keys)
				User.findOneAndUpdate({email: user.email}, { 
					folders: newFolders,
					staticPorts: newPorts,
					credentials: newCredentials,
					keys: updatedKeys
				}, (err, doc) => {
					if(err) {
						console.log(err)
						return
					}
					console.log("[INFO] updated user: " + user.email)
				})
				keys = results[0].keys
			}

			// initialize k8s namespace for user
			kubeapi.post('namespaces', createNamespace(user.namespace), async (err, result) => {
				if (err) {
					if (!(err.reason == 'AlreadyExists')) {
						console.log(err)
					}
				}
				try{
					// create k8s secret with keys for user
					await deleteAndCreateSecret(user.namespace, keys, 'keys')
					res.status(200).send({
						"token": userToken,
						"user": user.email
					})
				} catch(err) {
					console.log(err)
					res.status(500).send()
				}
			})
		} catch(err) {
			console.log(err)
			res.status(500).send()
		}
	})
})

function checkSshConnection(adaptor) {
	return new Promise((resolve, reject) => {
		const conn = new ssh()
		conn.on('error', (err) => {
			resolve(false)
		})
		conn.on('ready', () => {
			resolve(true)
		}).connect({
			host: adaptor.host,
			username: adaptor.user,
			port: 22,
			privateKey: adaptor.keys.private
		})
	})
}

function copySshId(adaptor) {
	let doneCnt = 2
	function done(cb) {
		doneCnt -= 1
		if (doneCnt == 0) {
			cb()
		}
	}
	console.log("[SSH] connecting", adaptor)
	return new Promise((resolve, reject) => {
		const conn = new ssh()
		conn.on('error', (err) => {
			console.log("[SSH] ERRROR [" + adaptor.host + "]: "  + err)
			reject(err)
		})
		conn.on('ready', () => {
			console.log("[SSH] connected to: " + adaptor.host);
			conn.sftp((err, sftp) => {
				if (err) {
					reject(err)
					return
				}
				sftp.appendFile('.ssh/authorized_keys', adaptor.keys.public + '\n', (err) => {
					if (err) { 
						reject(err)
						return
					}
					console.log("[SSH] added public key to: " + adaptor.host)
					done(resolve)
				})
				sftp.writeFile('.ssh/' + adaptor.keys.idFile, adaptor.keys.private + '\n', {mode: '0600'}, (err) => {
					if (err) {
						reject(err)
						return
					}
					console.log("[SSH] added private key to: " + adaptor.host)
					done(resolve)
				})
			})
		}).connect({
			host: adaptor.host,
			username: adaptor.user,
			port: 22,
			privateKey: adaptor.privateKey ? decodeBase64(adaptor.privateKey) : null,
			password: adaptor.password || adaptor.pwd
		})
	})
}

async function getNamespaceServices(ns) {
	const res = await kubeapi.get('namespaces/' + ns + '/services')
	return res
}

async function getNamespacePods(ns) {
	const res = await kubeapi.get('namespaces/' + ns + '/pods')
	res.items.forEach(d => {
		console.log("[INFO] namespace: " + ns + ", pod: " + d.metadata.name);
	})
	return res
}

function getNamespaceDeployments(ns) {
	return new Promise((resolve, reject) => {
		kubeext.get('namespaces/' + ns + '/deployments/', (err, res) => {
			if (err) {
				console.log(err)
				reject(err)
				return
			}
			const deployments = res.items.map(d => {
				return d.metadata.name
			})
			resolve(deployments)
		})

	})
}

function filterPods(pods) {
	return pods.filter(p => {
		return p.status.containerStatuses
	}).map(p => {
		const r = {}
		r.name = p.metadata.name
		r.containers = p.status.containerStatuses.map(c => {
			return {
				name: c.name,
				state: Object.keys(c.state)[0],
				image: c.image
			}
		})
		return r
	})
}

function filterServices(services) {
	return services.map(s => {
		return {
			type:  s.metadata.labels.type,
			name:  s.metadata.name,
			ports: s.spec.ports.map(p => p.nodePort),
			entryEndpoints:  config.entryEndpoints
		}
	})
}


app.post(api + '/restart', checkToken, async(req, res) => {
	const infra = req.body
	if(!infra.name) {
		res.status(404).send()
		return
	}
	const deployment = deploymentDb[infra.name]
	if(!deployment) {
		res.status(404).send()
		return
	}

	try {
		// create k8s deployment
		updateInfraStatus(infra.name, "deploying pod", deployment)
		
		const deployments = await getNamespaceDeployments(req.user.namespace)
		if (deployments.includes(infra.name)) {
			kubeext.delete('namespaces/' + req.user.namespace + '/deployments/' + infra.name, async (err, r) => {
				if (err) 	console.log(err)
				else {
					await kubeext.post('namespaces/' + req.user.namespace + '/deployments', deployment)
					console.log("[INFO] restarted infra: " + infra.name)
					res.status(200).send("Ok")
				}
			})
		} else {
			await kubeext.post('namespaces/' + req.user.namespace + '/deployments', deployment)
			console.log("[INFO] restarted infra: " + infra.name)
			res.status(200).send("Ok")
		}
	} catch(err) {
		res.status(500).send(err)
	}

})

app.get(api + '/infrastructure', checkToken, async(req, res) => {
	const services = await getNamespaceServices(req.user.namespace)
	const pods = await getNamespacePods(req.user.namespace)
	//console.log(JSON.stringify(pods, null, 2))
	info = {}
	info.services = filterServices(services.items)
	info.pods = filterPods(pods.items)
	info.token = {
		type: 'token',
		header: 'x-access-token',
		value: req.user.keys.token
	}
	res.status(200).send(info)
})

app.delete(api + '/node/:id', async(req, res) => {
	const id = req.params.id
	console.log("[INFO] deleting node " + id)
	deleteCloudifyDeployment(id)
	removeNode(id)
	res.status(200).send()
})

app.delete(api + '/infrastructure/:id', checkToken, async(req, res) => {
	const id = req.params.id
	const result = {
		status: "OK",
		errors: []
	}
	kubeext.delete('namespaces/' + req.user.namespace + '/deployments/' + id, (err, r) => {
		if (err) {
			result.status = "WITH_ERRORS"
			result.errors.push(err)
		}
		res.status(200).send(result)
		/*kubeapi.delete('namespaces/' + req.user.namespace + '/services/' + id, (err, r) => {
			if (err) {
				result.status = "WITH_ERRORS"
				result.errors.push(err)
			}
			res.status(200).send(result)
		})*/
	})
})

const getNextPort = function() {
	let port = 9000
	return function() {
		return port++
	}
}()

function checkAvailableResources(infra) {
	updateInfraStatus(infra.name, "checking resources")
	return new Promise(async (resolve, reject) => {
		if(!infra.dedicatedNode) {
			resolve([])
			return
		}
		
		const name = infra.name
		const nodes = await updateAndCleanNodes()
		const filteredNodes = Object.keys(nodes).filter(n => {
			if(n.indexOf(name) > -1) return n
		})

		if(!isEmpty(filteredNodes)) {
			resolve(filteredNodes)
			return
		}

		if(!config.cloudify) {
			resolve([])
			return
		}

		o = {
			blueprint_id: config.cloudify.blueprintId,
			inputs: {
				master: config.k8s.master,
				token: config.k8s.token,
				discovery_ca: config.k8s.discoveryCa
			}
		}

		function install() {
			getCloudifyDeployments().then(res => {
				res.items.forEach(d => {
					cloudifyDeployments[d.id] = d
					console.log('[INFO] found cloudify deployment: ', d.id)
				})
				installCloudifyDeployment(name).then(res => {
					console.log(res)
				}).catch(e => {
					console.log(e)
				})
			})
		}

		createCloudifyDeployment(name, o).then(res => {
			console.log("[INFO] installing node ", name)
			setTimeout(() => {
				install()
			}, 10000)
		}).catch(err => {
			if (err instanceof AlreadyExistsError) {
				console.log("[INFO] installing node ", name)
				setTimeout(() => {
					install()
				}, 10000)
			} else {
				console.log(err)
			}
		})
		
		waitForNodeUp(infra.name).then(n => {
			console.log("[INFO] node up: ", n)
			resolve(n)
		}).catch(err => {
			reject("node up error")
		})
	})
}

function updateInfraStatus(name, status, details) {
	if(!infras[name]) {
		infras[name] = {}
	}
	infras[name][status] = status
	infras[name][details] = details
}

function stripInfoFromInfra(i) {
	const c = JSON.parse(JSON.stringify(i))
	const allowFields = ['name', 'type', 'host', 'path', 'user']
	c.storageAdaptorContainers.forEach(s => {
		const fieldsToRemove = []
		Object.keys(s).forEach(k => {
			if(!allowFields.includes(k)) {
				fieldsToRemove.push(k)
			}
		})
		fieldsToRemove.forEach(f => {
			delete s[f]
		})
	})
	
	c.logicContainers.forEach(s => {
		const fieldsToRemove = []
		Object.keys(s).forEach(k => {
			if(!allowFields.includes(k)) {
				fieldsToRemove.push(k)
			}
		})
		fieldsToRemove.forEach(f => {
			delete s[f]
		})
	})

	return c
}

function updateDict(ot, nt) {
	Object.keys(nt).forEach(k => {
		const v = nt[k]
		ot[k] = v
	})
	return ot
}

function updateFolders(of, nf){
	const nfht = {}
	const ofht = {}
	nf.filter(i => { return i }).forEach(i => {
		nfht[i.name] = i
	})
	of.filter(i => { return i }).forEach(i => {
		ofht[i.name]  = i
	})

	const subFolders = of.filter(i=>{return i}).map(f => {
		if(nfht[f.name]){
			return nfht[f.name]
		} else return f
	})

	const newFolders = nf.filter(f => {
		if(!ofht[f.name]) return f
	})

	return subFolders.concat(newFolders)
}

function updateUserFolders(user, folder) {

	return new Promise((resolve, reject) => {
		User.findById(user._id, (err, doc) => {
			if(err) {
				//console.log(err)
				reject(err)
				return
			}
			let newFolders = []
			if(doc.folders) {
				let sub = false
				newFolders = doc.folders.map((f,i) => {
					if(f.name == folder.name) {
						sub = true
						return folder
					} else return f
				})
				if(!sub) {
					newFolders.push(folder)
				}
				console.log("[INFO] newFolders: ", newFolders)
			} else {
				newFolders.push(folder)
			}
			User.findByIdAndUpdate(user._id, {folders: newFolders}, (err, doc) => {
				if(err) {
					reject(err)
					//console.log(err)
					return
				}
				console.log("[INFO] updated user " + user.email + " with folder: " + folder)
				resolve(doc)
			})
		})
	})
}

app.post(api + '/infrastructure', [checkToken], async(req, res) => {
//app.post(api + '/infrastructure', async(req, res) => {
	const infra = req.body

	let cntPort = 3001
	const response = {}
	const services = []
	const claims = []
	const adaptorDescriptions = []
	const volumes = createVolume()

	infras[infra.name] = {
		id: infra.name,
		status: "queued"
	}
	
	res.status(200).send(infras[infra.name])
	
	infra.storageAdaptorContainers = infra.storageAdaptorContainers || []
	infra.initContainers = infra.initContainers || []
	const clonedInfra = stripInfoFromInfra(infra)
	clonedInfra.folders = req.user.folders

	checkAvailableResources(infra).then(async deployNodes => {
		if(infra.deployNode) {
			deployNodes.push(infra.deployNode)
		}
		// convert description to k8s container list
		const sshPromises = infra.storageAdaptorContainers.filter(adaptor => {
			return adaptor.type == "sshfs"
		}).map(async(adaptor, index) => {
			adaptor.keys = req.user.keys.ssh
			// create ssh keys
			if(!(await checkSshConnection(adaptor))) {
				try {
					await copySshId(adaptor)
				}catch(err) {
					const e = {
						host: adaptor.host,
						name: adaptor.name,
						error: err
					}
					console.log(err)
					//res.status(500).send(e)
					return
				}
			} else {
				console.log("[SSH] key already present: " + adaptor.host)
			}

			try {
				await updateUserFolders(req.user, {
					host: adaptor.host,
					name: adaptor.name,
					user: adaptor.user,
					folder: adaptor.path,
					type: "hpc_node",
					access: [adaptor.type]
				})
			} catch(err) {
				console.log("[ERROR] error updating user info: ", err)
				//infras[infra.name]['status'] = "error"
				//infras[infra.name]['error'] = err
			}


			// create container descriptions
			cntPort += 1
			const u = moduleHolder['sshfs']({
				name: adaptor.name,
				namespace: req.user.namespace,
				containerPort: cntPort,
				sshHost: adaptor.host,
				sshPort: adaptor.port || '22',
				sshUser: adaptor.user,
				sshPath: adaptor.path
			})
			const desc = {
				name: adaptor.host,
				host: 'localhost',
				port: cntPort,
				type: 'webdav',
				mount: adaptor.path
			}
			adaptorDescriptions.push(desc)
			return u
		})

		let sshContainers = await Promise.all(sshPromises)
		sshContainers = sshContainers.filter(c => {
			return c
		})

		const ports = {}
		async function processContainers(c, index) {
			if(!moduleHolder[c.type]) {
				console.log("[ERROR] " + c.type + " not found.")
				return
			}
			c.adaptors = sshContainers
			c.descriptions = adaptorDescriptions
			c.user = req.user
			c.env = c.env || {}
			c.containerPort = c.port ||  getNextPort()
			ports[c.name] = c.containerPort

			const u = moduleHolder[c.type](c)
			if(c.service) {
				const s = createService({
					name: c.name,
					iname: infra.name,
					namespace: req.user.namespace,
					targetPort: c.service.targetPort || c.containerPort,
					type: c.type,
					staticPorts: req.user.staticPorts || {}
				})
				ports[c.name] = c.service.targetPort || c.containerPort
				services.push(s)
			}

			/*if(c.sharedMountPath) {
				u.volumeMounts.push({
					name: "shared-data",
					mountPath: c.sharedMountPath
				})
			}*/

			if(c.mountHost && infra.deployNode) {
				const userNamespace = req.user.namespace
				const userFolders = req.user.folders || []
			
				// create mount
				c.mountHost.forEach((mnt, i) => {
					const isAuthorized = userFolders.some(f => {
						//return (f.host == infra.deployNode && mnt.hostPath == f.folder && f.type == "k8s_node")	
						return (f.host == infra.deployNode && mnt.hostPath == f.folder)	
					})
					// check authorization
					if(!isAuthorized) {
						console.log("[INFO] " + userNamespace + " not authorized to mount " + mnt.hostPath + " on " + infra.deployNode)
						return;
					}
					const vol = {
						name: "volume-" + i,
						hostPath: {
							path: mnt.hostPath
						}
					}
					volumes.push(vol);
					u.volumeMounts.push({
						name: "volume-" + i,
						mountPath: mnt.mountPath
					})
				});
			}
			return u
		}

		updateInfraStatus(infra.name, "generating k8s yaml")

		// create logic containers
		const lgPromises = infra.logicContainers.map(processContainers)
		const lgContainers = await Promise.all(lgPromises)
		lgContainers.forEach(c => {
				Object.keys(ports).forEach(k => {
					const v = ports[k]
					c.env.push({
						name: k.toUpperCase() + "_HOST",
						value: "127.0.0.1:" + v
					})
				})
				c.env.push({
					name: "INFRA",
					value: encodeBase64(JSON.stringify(clonedInfra))
				})
				c.env.push({
					name: "SSH_PRIVATE_KEY",
					value: encodeBase64(req.user.keys.ssh.private)
				})
				c.env.push({
					name: "SSH_PUBLIC_KEY",
					value: encodeBase64(req.user.keys.ssh.public)
				})
				c.env.push({
					name: "ID_RSA_FILENAME",
					value: encodeBase64(req.user.keys.ssh.idFile)
				})
		})
		
		// create init containers
		const initPromises = infra.initContainers.map(processContainers)
		const initContainers = await Promise.all(initPromises)

		const containers = sshContainers.concat(lgContainers)


		let yml = ""
		services.forEach(s => {
			yml += YAML.stringify(s)
			yml += "---\n"
		})
		
		if (!options.noDeploy) {
			//try{

				// create k8s services
				// wait for all async calls to return
				await Promise.all(services.map(async s => {
						kubeapi.delete('namespaces/' + req.user.namespace + '/services/' + s.metadata.name, async (err, res) => {
							if (err) console.log(err)
							
							const r = await kubeapi.post('namespaces/' + req.user.namespace + '/services', s)
							const serviceName = r.metadata.labels.type.toUpperCase() + "_SERVICE"
							const host = 'lobcder.process-project.eu:' + r.spec.ports[0].nodePort
							containers.forEach(c => {
								c.env.push({
									name: serviceName,
									value: host
								})
							})
						})
					})
				)
				// generate k8s YAML deployment
				const deployment = createDeployment({
					name: infra.name,
					namespace: req.user.namespace,
					location: infra.location,
					deployNodes: deployNodes
				}, volumes, containers, initContainers)

				yml += YAML.stringify(deployment)
				//console.log("[INFO] deployment: ", yml)

				// save locally so it cn be restarted
				deploymentDb[infra.name] = deployment
				
				// create k8s deployment
				updateInfraStatus(infra.name, "deploying pod", deployment)

				
				const deployments = await getNamespaceDeployments(req.user.namespace)
				if (deployments.includes(infra.name)) {
					kubeext.delete('namespaces/' + req.user.namespace + '/deployments/' + infra.name, async (err, res) => {
						if (err) console.log(err)
						else {
							await kubeext.post('namespaces/' + req.user.namespace + '/deployments', deployment)
						}
					})
				} else {
					await kubeext.post('namespaces/' + req.user.namespace + '/deployments', deployment)
				}
			//} catch (err) {
			//	console.log("Error deploying: " + JSON.stringify(err))
			//}
		}

		//res.status(200).send(YAML.parseAllDocuments(yml))

	}).catch(err => {
		console.log(err)
	})
})

function deploy(desc) {
	const yamlFile = 'deployments/' + req.user.namespace + "." + infra.name + '.yaml'
	fs.writeFileSync(yamlFile, desc, 'utf-8')
}

const userSchema = mongoose.Schema({
	email: String,
	namespace: String,
	keys: Object,
	folders: Object,
	staticPorts: Object,
	credentials: Object
})


const User = mongoose.model('Users', userSchema)

async function checkMongo() {
	const user = config.mongodb.user
	const pwd = config.mongodb.pwd
	const url = "mongodb://" + user + ":" + pwd + "@" + options.mongo + ":27017/process"
	//console.log(url)
	mongoose.connect(url)
	const db = mongoose.connection
	db.on('error', console.error.bind(console, "conn error"))
	db.once('open', () => {
		console.log('[INFO] connected to mongodb')
	})
}

function updateKeys(k) {
	if(k.ssh.idFile) return k
	const privateSshKeyHash = md5sum(k.ssh.private)
	k.ssh.idFile = "process_id_rsa_" + privateSshKeyHash
	return k
}

function generateKeys(user) {
	return new Promise((resolve, reject) => {
		const pair = keypair();
		const publicSshKey = forge.ssh.publicKeyToOpenSSH(forge.pki.publicKeyFromPem(pair.public), user.user + '@process-eu.eu')
		const privateSshKey = forge.ssh.privateKeyToOpenSSH(forge.pki.privateKeyFromPem(pair.private), user.user + '@process-eu.eu')
		const privateSshKeyHash = md5sum(privateSshKey)
		const idRsaFilename = "process_id_rsa_" + privateSshKeyHash

		jwt.sign({
			email: user.email,
			idFile: idRsaFilename
		}, pair.private, {algorithm: 'RS256'}, (err, token) => {
			if (err) reject(err)
			resolve({
				ssh: {
					public: publicSshKey,
					private: pair.private,
					idFile: idRsaFilename
				},
				raw: pair,
				token: token
			})
		})
	})
}

class AlreadyExistsError extends Error {
}

function installCloudifyDeployment(deployName) {

	if(!cloudifyDeployments[deployName]) {
		return Promise.reject(new Error("cloudify deployment not found " + deployName))
	}

	const options = {
		method: "POST",
		uri: config.cloudify.uri + 'executions?_include=id',
		rejectUnauthorized: false,
		headers: {
			"Tenant": "default_tenant",
			"Content-Type": "application/json"
		},
		body: {
			deployment_id: deployName,
			workflow_id: "install"
		},
		json: true
	}
	return rp(options)
}

function createCloudifyDeployment(deployName, body) {
	if(cloudifyDeployments[deployName]) {
		return Promise.reject(new AlreadyExistsError("[warning] cloudify deployment " + deployName + " already exists."))
	}
	const options = {
		method: "PUT",
		uri: config.cloudify.uri + 'deployments/' + deployName,
		rejectUnauthorized: false,
		headers: {
			"Tenant": "default_tenant",
			"Content-Type": "application/json"
		},
		body: body,
		json: true
	}
	return rp(options)
}

function deleteCloudifyDeployment(deployName) {

	const options = {
		method: "POST",
		uri: config.cloudify.uri + 'executions?_include=id',
		rejectUnauthorized: false,
		headers: {
			"Tenant": "default_tenant",
			"Content-Type": "application/json"
		},
		body: {
			deployment_id: deployName,
			workflow_id: "uninstall"
		},
		json: true
	}
	return rp(options)
}

function getCloudifyDeployments() {
	const options = {
		method: "GET",
		uri: config.cloudify.uri + 'deployments',
		rejectUnauthorized: false,
		headers: {
			"Tenant": "default_tenant",
			"Content-Type": "application/json"
		},
		json: true
	}
	return rp(options)
}

if(config.cloudify) {
	promiseRetry((retry, number) => {
		console.log('[INFO] retrying to contact cloudify at: ', config.cloudify.uri)
		return getCloudifyDeployments().catch(retry)
	}).then(res => {
		console.log('[INFO] connected to cloudify: ', config.cloudify.uri)
		// console.log('current deployments: ', res)
		res.items.forEach(d => {
			cloudifyDeployments[d.id] = d
			console.log('[INFO] found cloudify deployment: ', d.id)
			//console.log(d)
		})
	})
} else {
	console.log("[INFO] skipping cloudify check.")
}


try {
	// load container handlers
	loadModules('./containers')
	watchModules('./containers')

	// generate debug token
	const adminToken = generateToken("admin", "default")
	console.log("[INFO] admin token: ", adminToken)
	fs.writeFileSync("./adminToken", adminToken)
}
catch(err) {
	console.log("[ERROR] error booting up: ", err)
}


// start HTTPS server
//console.log("Starting secure server...")
//httpsServer.listen(options.port || 4243)

// start HTTP server
console.log("[INFO] Starting server...")
httpServer.listen(options.port || 4200)
