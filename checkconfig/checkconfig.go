package checkconfig

import (
	"os"
	"webhook-server/configstruct"
	"webhook-server/filehandling"
	"webhook-server/k8shub"
	"webhook-server/loghub"
)

// Init the settings check
func Init() {
	loghub.Out(0, "Checking config ...", false)

	/*
		Settings checks
	*/
	checkPortUint(configstruct.CurrentConfig.WebhookServer.Settings.Listenport, "listenport")
	/*
		Security checks
	*/
	checkEmptyRootCA(configstruct.CurrentConfig.WebhookServer.Security.RootCADir)
	filehandling.CreateDir(configstruct.CurrentConfig.WebhookServer.Security.RootCADir)
	checkEmptyIntCA(configstruct.CurrentConfig.WebhookServer.Security.IntCADir)
	filehandling.CreateDir(configstruct.CurrentConfig.WebhookServer.Security.IntCADir)
	checkEmptyPubCertPoolDir(configstruct.CurrentConfig.WebhookServer.Security.PubCertPoolDir)
	filehandling.CreateDir(configstruct.CurrentConfig.WebhookServer.Security.PubCertPoolDir)
	checkEmptySrvCrtDir(configstruct.CurrentConfig.WebhookServer.Security.ServerCertDir)
	filehandling.CreateDir(configstruct.CurrentConfig.WebhookServer.Security.ServerCertDir)
	checkEmptyTempCertDir(configstruct.CurrentConfig.WebhookServer.Security.TempCertDir)
	filehandling.CreateDir(configstruct.CurrentConfig.WebhookServer.Security.TempCertDir)
	checkEmptyEternityDir(configstruct.CurrentConfig.WebhookServer.Security.EternityDir)
	filehandling.CreateDir(configstruct.CurrentConfig.WebhookServer.Security.EternityDir)
	checkEmptyDNSAltNames(configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames)
	checkEmptyIPAltNames(configstruct.CurrentConfig.WebhookServer.Security.IPAltNames)
	checkEmptyAllowedAccounts(configstruct.CurrentConfig.WebhookServer.Security.AllowedAccounts)
	/*
		Kubernetes checks
	*/
	//bool checks for "enabled" or "auto-eternity" are not necessary
	checkK8SNamespace()   //namespace must go first
	checkK8SCM()          //check if configmap is empty
	checkK8SSec()         //check if secret is empty
	checkK8SServiceName() //check if service name is empty
	loghub.Out(3, "Passed kubernetes checks", false)

	//Success message
	loghub.Out(0, "Config valid! Ready for launch!", false)
}

// check given uint16 for validity of range and exceptions
func checkPortUint(port uint16, ep string) {
	if port == 0 {
		switch ep {
		case "listenport":
			configstruct.CurrentConfig.WebhookServer.Settings.Listenport = 443
		default:
			loghub.Out(2, "Not funny ...", true)
		}
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	} else {
		//we want to restrict some port allocations
		portArray := [2]uint16{0, 22} //no 0, no SSH
		for _, v := range portArray {
			if port == v {
				loghub.Out(2, "Use of forbidden port detected (0, 22)!", true)
			}
		}
	}
}

func checkEmptyRootCA(dir string) {
	if dir == "" {
		configstruct.CurrentConfig.WebhookServer.Security.RootCADir = "./webhook-server/root-ca-dir"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyIntCA(dir string) {
	if dir == "" {
		configstruct.CurrentConfig.WebhookServer.Security.IntCADir = "./webhook-server/int-ca-dir"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyPubCertPoolDir(dir string) {
	if dir == "" {
		configstruct.CurrentConfig.WebhookServer.Security.PubCertPoolDir = "./webhook-server/pub-cert-pool-dir"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptySrvCrtDir(dir string) {
	if dir == "" {
		configstruct.CurrentConfig.WebhookServer.Security.ServerCertDir = "./webhook-server/server-cert-dir"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyTempCertDir(dir string) {
	if dir == "" {
		configstruct.CurrentConfig.WebhookServer.Security.TempCertDir = "./webhook-server/temp-cert-dir"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyEternityDir(dir string) {
	if dir == "" {
		configstruct.CurrentConfig.WebhookServer.Security.EternityDir = "./webhook-server/eternity-dir"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyDNSAltNames(pool []string) {
	if len(pool) == 0 {
		pool = append(pool, "webhook-server-svc.default.svc")
		configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames = pool
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyIPAltNames(pool []string) {
	if len(pool) == 0 {
		pool = append(pool, "127.0.0.1")
		configstruct.CurrentConfig.WebhookServer.Security.IPAltNames = pool
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkEmptyAllowedAccounts(pool []string) {
	if len(pool) == 0 {
		pool = append(pool, "system:serviceaccount:kube-system:default")
		configstruct.CurrentConfig.WebhookServer.Security.IPAltNames = pool
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkK8SCM() {
	if configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap == "" {
		configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap = "webhook-server-cm"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkK8SSec() {
	if configstruct.CurrentConfig.WebhookServer.Kubernetes.Secret == "" {
		configstruct.CurrentConfig.WebhookServer.Kubernetes.Secret = "webhook-server-sec"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func checkK8SNamespace() {
	if os.Getenv("WHS_K8S_NAMESPACE") == "" {
		if configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace == "" {
			configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace = "default"
		}
	} else {
		configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace = os.Getenv("WHS_K8S_NAMESPACE")
	}
	k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
}

func checkK8SServiceName() {
	if configstruct.CurrentConfig.WebhookServer.Kubernetes.ServiceName == "" {
		configstruct.CurrentConfig.WebhookServer.Kubernetes.ServiceName = "webhook-server-svc"
		k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
	}
}

func SetDNSAltNames() {
	pool := configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames
	svcname := configstruct.CurrentConfig.WebhookServer.Kubernetes.ServiceName
	ns := configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace
	fqdnLight := svcname + "." + ns + ".svc"
	fqdnFull := svcname + "." + ns + ".svc.cluster.local"
	names := []string{fqdnLight, fqdnFull}

	hit := false
	for _, n := range names {
		hit = false
		for _, i := range pool { //avoid double entries
			if i == n {
				hit = true
			}
		}
		if !hit {
			pool = append(pool, n)
			loghub.Out(3, "Added DNS "+n+" to certificate", false)
		}
	}
	configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames = pool
	k8shub.UpdateConfigMap(configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap, configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace)
}
