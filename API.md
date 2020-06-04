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
