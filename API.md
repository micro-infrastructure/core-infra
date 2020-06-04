# Core-infra REST API
### PUT /api/v1/user

- Description: Create user
- Requirements: admin x-access-token header
- Payload type: json
- Payload example:

```{
    "email": "test@process-project.eu",
    "namespace": "test",
    "folders": [
        {    
            "name": "example",
            "host": "example.com",
            "user": "user",
            "access": ["ssh"],
            "folder":"host_path",
            "type": "k8s_node"
        },
    "staticPorts": 
        {
            "webdav": 31002
            "scp": 31001
            "jupyter": 31003
        }
```
- Response example:
```
{
    "token": "eyJhb...",
    "user": "test@process-project.eu"
}
```

### GET /api/v1/infrastructure
- Description: Get k8s endpoint and container description/status. This is used to get the ports on which the services are exposed and to to get the user service token to be used with LOBCDER user services such as LOBCDER-copy. N.B. this token is a different token than the one given when a user is created.
- Requirements: user infra x-access-token header
- Response type: JSON
- Response example:
```
{
	"token": {
    	"type": "token",
        "header": "x-access-token"
        "token": "eYJh..."
    },
    "services": [
        {
            "type": "scp",
            "name": "uc1-123-scp",
            "ports": [
                31138
            ],
            "host": "lobcder.process-project.eu"
        },
        {
            "type": "webdav",
            "name": "uc1-123-webdav",
            "ports": [
                31408
            ],
            "host": "lobcder.process-project.eu"
        }
    ],
    "pods": []

```

### POST /api/v1/infrastructure
- Description: Create a micro-infrastructure. This call creates a k8s deployment for the user and deploys the containers on the k8s cluster.
- Requirement: user infra x-access-token
- Payload type: JSON
- Payload example:
```
{
    "name": "example",
    "namespace": "USER",
    "dedicatedNode": false,
    "deployNode": "NODE",
    "storageAdaptorContainers": [
        {
            "name": "NAME",
            "type": "sshfs",
            "expose": "webdav",
            "user": "USER",
            "password":"",
            "host": "HOST",
            "path": "PATH"
        }
    "logicContainers": [
     	{ "name": "redis", "type": "redis" },
        { "name": "proxy", "type": "proxy" },
        {
            "name": "NAME",
            "type": "generic",
            "image": "IMAGE",
            "env": [
                { "name": "TEST_ENV", "value": "hello" }
            ],
            "mountHost": [
                { "hostPath": "PATH", "mountPath": "/data" }                           			 ],
            "port": 3000,
            "service": {
                "enabled": true
            },
            "cmd": ["START_COMMANDS"]
        },
        {
            "name": "scp",
            "type": "scp",
            "service": {
                "enabled": true
            }
        }
        ]
        
```

### DELETE /api/v1/infrastructure/:name
- Description: Deletes a user micro-infrastructure
- Requirements: 
	 - infra x-access-token
	 - name of micro-infrastructure
- Response 200 example:
```
{
    "status": "OK",
    "errors": []
}
``` 
