### Kubernetes Webhook Server

This is intended to run only in Kubernetes so build an image (see build-docker-win.bat) and run it in your Kubernetes cluster.

As of now it only serves audit validations and denials but it is highly customizable.

#### Basic functionality

- TLS self-provisioning at startup
- TLS adjustments via Kubernetes secret
- Config adjustments via Kubernetes configmap
- Follows default Kubernetes ValidatingWebhookConfigurations

#### Usage

- Create a deployment with respective configmap (see ./deployment directory) to fit your needs
- Start the deployment and get the caBundle value from the self-creating ValidatingWebhookConfiguration called "mywebhook.template.io"
- Create a ValidatingWebhookConfiguration with the caBundle value you got and adjust rules to your need

| Paths | Function |
|---|---|
| /readyz | is just a default "ok" to see if everything works as intended |
| /user-audit| shows user activity for your active |
| /user-deny | denies all users except the allowedAccount (in your configmap) for actions that you defined in your ValidatingWebhookConfiguration |


#### Default behaviour

- The namespace is "webhook-hub"
- The service name is "webhook-server-svc"
- FQDN gets generated for webhook usage
- If you do not specify a configMap at startup it creates a default template configmap in the namespace "default"
- Certificates get auto-created for all FQDNs and/or changes in DNSAlternative/IPAlternative fields in the configmap

#### Eternal TLS

- You can enable auto-eternity after mounting your certificates to /kubernetes-certs and trigger an eternal certificate cycle after each restart of the pods

### Completion

The code for TLS is complete.
The code for Secret/ConfigMap handling is 99% ok but I sense some bugs.
The code for webhook handling is complete and easily extendable.

### Ideas

None so far. Just testing and fixing.

