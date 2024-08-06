package k8shub

import (
	"context"
	"log"
	"os"
	"webhook-server/configstruct"
	"webhook-server/filehandling"
	"webhook-server/loghub"

	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// at startup within kubernetes we need these static entries
// I know that global variables are BS but certificates have to be handled REALLY precise (we cannot dynamically "guess" what key and what cert matches)
// if someone wants to provide own certificates just rename them
var rootCertName = "webhook-server-root-ca.crt"
var rootKeyName = "webhook-server-root-ca.key"
var intCertName = "webhook-server-int-ca.crt"
var intKeyName = "webhook-server-int-ca.key"

// create in-cluster kubernetes config. This config is tied to the serviceaccount the pod uses
// this enables native RBAC usage
func createInClusterConfig() *rest.Config {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal("Unable to load in-cluster config:", err)
	}
	return config
}

// this is our first entry to some kubernetes functionality
// it mainly is the first contact for the configMap update at startup
// all further functions are TBD
func Init() {
	ns := os.Getenv("WHS_K8S_NAMESPACE")
	cm := configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap

	if !UpdateConfigMap(cm, ns) {
		loghub.Out(2, "Failed to update configmap", true)
	}
}

// UpdateConfigMap loads the current configuration the app has, marshals these values to YAML and updates the "config.yml" field with these values within the given ConfigMap name
// the "local" approach is necessary since the app can be ahead of the cluster ConfigMap
// a redeploy is not necessary --> see "deleteSelf()" function comment for explanation
func UpdateConfigMap(cmap string, ns string) bool {
	config := createInClusterConfig()            //get cluster config
	client, _ := kubernetes.NewForConfig(config) //set client

	exists := true
	configMap, err := client.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmap, metav1.GetOptions{}) //see if cm exists
	if err != nil {
		loghub.Out(2, err.Error(), false)
		exists = false
		configMap = nil
		configMap = getEmptyConfigMap(cmap, ns)
	}

	output, outputErr := yaml.Marshal(configstruct.CurrentConfig) //get live config and marshal to byte array
	if outputErr != nil {
		log.Println(outputErr)
		return false
	}

	configData := output
	configMap.Data["config.yml"] = string(configData) //enrich cm object with live data

	if exists {
		_, updateErr := client.CoreV1().ConfigMaps(ns).Update(context.TODO(), configMap, metav1.UpdateOptions{})
		if updateErr != nil {
			return false
		}
	} else {
		_, createErr := client.CoreV1().ConfigMaps(ns).Create(context.TODO(), configMap, metav1.CreateOptions{})
		if createErr != nil {
			return false
		}
	}

	loghub.Out(0, "Updated configmap "+cmap+" in namespace "+ns, false)
	return true
}

func UpdateSecret(sec string, ns string) bool {
	config := createInClusterConfig()
	client, _ := kubernetes.NewForConfig(config)

	exists := true
	secret, err := client.CoreV1().Secrets(ns).Get(context.TODO(), sec, metav1.GetOptions{})
	if err != nil {
		loghub.Out(2, err.Error(), false)
		exists = false
		secret = nil
		secret = getEmptySecret(sec, ns)
	}
	//fullpath to all files
	rootCertFile := configstruct.CurrentConfig.WebhookServer.Security.RootCADir + "/" + rootCertName
	rootKeyFile := configstruct.CurrentConfig.WebhookServer.Security.RootCADir + "/" + rootKeyName
	intCertFile := configstruct.CurrentConfig.WebhookServer.Security.IntCADir + "/" + intCertName
	intKeyFile := configstruct.CurrentConfig.WebhookServer.Security.IntCADir + "/" + intKeyName
	//byte arrays of all files
	rootCertBytes := filehandling.ReadFileBytes(rootCertFile)
	rootKeyBytes := filehandling.ReadFileBytes(rootKeyFile)
	intCertBytes := filehandling.ReadFileBytes(intCertFile)
	intKeyBytes := filehandling.ReadFileBytes(intKeyFile)
	//enrich secret with data
	secret.Data[rootCertName] = rootCertBytes
	secret.Data[rootKeyName] = rootKeyBytes
	secret.Data[intCertName] = intCertBytes
	secret.Data[intKeyName] = intKeyBytes

	//special auto-eternity case
	if configstruct.CurrentConfig.WebhookServer.Kubernetes.AutoEternity {
		eKeyType := configstruct.CurrentConfig.WebhookServer.Security.CAType
		eKeyStrength := configstruct.CurrentConfig.WebhookServer.Security.CAStrength
		eternityRootKeyName := "eternity_root_" + eKeyType + "_" + eKeyStrength + ".key"
		eternityIntKeyName := "eternity_int_" + eKeyType + "_" + eKeyStrength + ".key"
		secret.Data[eternityRootKeyName] = rootKeyBytes
		secret.Data[eternityIntKeyName] = intKeyBytes
	}

	if exists {
		_, updateErr := client.CoreV1().Secrets(ns).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if updateErr != nil {
			return false
		}
	} else {
		_, createErr := client.CoreV1().Secrets(ns).Create(context.TODO(), secret, metav1.CreateOptions{})
		if createErr != nil {
			return false
		}
	}

	loghub.Out(0, "Updated secret "+sec+" in namespace "+ns, false)
	return true
}

func CreateTemplateValidationConfig() bool {
	config := createInClusterConfig()            //get cluster config
	client, _ := kubernetes.NewForConfig(config) //set client
	whname := "mywebhook.template.io"

	exists := true
	vConf, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.TODO(), whname, metav1.GetOptions{})
	if err != nil {
		loghub.Out(2, err.Error(), false)
		exists = false
		vConf = nil
		vConf = getEmptyValidationConf(whname) //always get a new "default" config to keep caBundle up-to-date
	}

	if exists {
		updatedConf := updateCABundle(vConf)
		_, updateErr := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(context.TODO(), updatedConf, metav1.UpdateOptions{})
		if updateErr != nil {
			loghub.Out(2, "Update CALL", false)
			loghub.Out(2, updateErr.Error(), false)
			return false
		}
	} else {
		_, createErr := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(context.TODO(), vConf, metav1.CreateOptions{})
		if createErr != nil {
			loghub.Out(2, "Create CALL", false)
			loghub.Out(2, createErr.Error(), false)
			return false
		}
	}

	loghub.Out(0, "Updated ValidatingWebhookConfiguration "+whname, false)
	return true
}

// this function is probably unnecessary since the kubelet does update e.g. ConfigMap contents in a sync period (~1 minute)
// all pods that mounted the ConfigMap will be "behind" up to 1m (insecure?)
// see https://kubernetes.io/docs/concepts/configuration/configmap/#mounted-configmaps-are-updated-automatically
// and https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/
func deleteSelf(config *rest.Config, podname string, ns string) {
	client, _ := kubernetes.NewForConfig(config)

	deleteErr := client.CoreV1().Pods(ns).Delete(context.TODO(), podname, metav1.DeleteOptions{})
	if deleteErr != nil {
		log.Println("Could not delete self")
	}
}

func updateCABundle(conf *v1.ValidatingWebhookConfiguration) *v1.ValidatingWebhookConfiguration {
	//template variables
	var webhooks []v1.ValidatingWebhook
	var uConf v1.ValidatingWebhook

	var sideeffects v1.SideEffectClass
	sideeffects = "None"

	var timeout int32
	timeout = 5

	var port int32
	port = int32(configstruct.CurrentConfig.WebhookServer.Settings.Listenport)

	var path string
	path = "/audit-user"

	//main settings
	uConf.AdmissionReviewVersions = []string{"v1"}
	uConf.SideEffects = &sideeffects
	uConf.TimeoutSeconds = &timeout

	var cservice v1.ServiceReference
	cservice.Name = configstruct.CurrentConfig.WebhookServer.Kubernetes.ServiceName
	cservice.Namespace = configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace
	cservice.Port = &port
	cservice.Path = &path

	var cconf v1.WebhookClientConfig
	cconf.Service = &cservice
	cconf.CABundle = configstruct.BytePublicChain

	uConf.ClientConfig = cconf
	uConf.Name = conf.Webhooks[0].Name

	//write webhook element to array
	webhooks = append(webhooks, uConf)

	var cfgraw v1.ValidatingWebhookConfiguration
	cfgraw = *conf

	cfgraw = v1.ValidatingWebhookConfiguration{

		TypeMeta: metav1.TypeMeta{
			Kind:       "ValidatingWebhookConfiguration",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            conf.ObjectMeta.Name,
			Namespace:       conf.ObjectMeta.Namespace,
			ResourceVersion: conf.ObjectMeta.ResourceVersion,
		},
		Webhooks: webhooks,
	}
	return &cfgraw
}

func getEmptySecret(sec string, ns string) *corev1.Secret {
	secraw := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sec,
			Namespace: ns,
		},
		Data: map[string][]byte{},
		Type: "Opaque",
	}
	return &secraw
}

func getEmptyConfigMap(cmap string, ns string) *corev1.ConfigMap {
	cfgraw := corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmap,
			Namespace: ns,
		},
		Data: map[string]string{},
	}
	return &cfgraw
}

// we may not want to start the template with rules enabled since it can cause deadlocks
func getEmptyValidationConf(name string) *v1.ValidatingWebhookConfiguration {
	//template variables
	var webhooks []v1.ValidatingWebhook
	var template v1.ValidatingWebhook
	var sideeffects v1.SideEffectClass
	sideeffects = "None"

	//var ruleOperations v1.OperationType
	//ruleOperations = "CREATE"

	//var scopeType v1.ScopeType
	//scopeType = "Namespaced"

	var port, timeout int32
	port = 443
	timeout = 5

	var path string
	path = "/audit-user"

	var cservice v1.ServiceReference
	cservice.Name = configstruct.CurrentConfig.WebhookServer.Kubernetes.ServiceName
	cservice.Namespace = configstruct.CurrentConfig.WebhookServer.Kubernetes.Namespace
	cservice.Port = &port
	cservice.Path = &path

	var cconf v1.WebhookClientConfig
	cconf.Service = &cservice
	cconf.CABundle = configstruct.BytePublicChain

	whname := name //musts be the same for webhooks and the main name
	//var ruleSet v1.RuleWithOperations
	//ruleSet.APIGroups = []string{""}
	//ruleSet.APIVersions = []string{"v1"}
	//ruleSet.Operations = []v1.OperationType{ruleOperations}
	//ruleSet.Resources = []string{"pods"}
	//ruleSet.Scope = &scopeType

	//set template values with correct bundle and dummy settings that work!
	template.Name = whname

	//client config
	template.ClientConfig = cconf

	//rules
	//template.Rules = []v1.RuleWithOperations{ruleSet}

	//main settings
	template.AdmissionReviewVersions = []string{"v1"}
	template.SideEffects = &sideeffects
	template.TimeoutSeconds = &timeout

	//write webhook element to array
	webhooks = append(webhooks, template)

	cfgraw := v1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ValidatingWebhookConfiguration",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: whname,
		},
		Webhooks: webhooks,
	}
	return &cfgraw
}

func CheckSecretExists() bool {
	sec := configstruct.CurrentConfig.WebhookServer.Kubernetes.Secret
	ns := os.Getenv("WHS_K8S_NAMESPACE")
	config := createInClusterConfig()
	client, _ := kubernetes.NewForConfig(config)
	_, err := client.CoreV1().Secrets(ns).Get(context.TODO(), sec, metav1.GetOptions{})
	if err != nil {
		return false
	}
	return true
}

// move files from secret mount to default workflow directories
// it is "safer" to do it this way since I hate the "shadow" references kubernetes secrets create at mount-time
func MoveK8SSecretCertificates() {
	//this is hardcoded since the user should not care about this path within the container
	//just make sure the user knows that the secret with all files should be mounted here (info in logs AND Readme)
	originDir := "./kubernetes-certs"
	eKeyType := configstruct.CurrentConfig.WebhookServer.Security.CAType
	eKeyStrength := configstruct.CurrentConfig.WebhookServer.Security.CAStrength
	eternityRootKeyName := "eternity_root_" + eKeyType + "_" + eKeyStrength + ".key"
	eternityIntKeyName := "eternity_int_" + eKeyType + "_" + eKeyStrength + ".key"
	//default copy without eternity keys
	filehandling.CopyAtoB(originDir+"/"+rootCertName, configstruct.CurrentConfig.WebhookServer.Security.RootCADir+"/"+rootCertName)
	filehandling.CopyAtoB(originDir+"/"+rootKeyName, configstruct.CurrentConfig.WebhookServer.Security.RootCADir+"/"+rootKeyName)
	filehandling.CopyAtoB(originDir+"/"+intCertName, configstruct.CurrentConfig.WebhookServer.Security.IntCADir+"/"+intCertName)
	filehandling.CopyAtoB(originDir+"/"+intKeyName, configstruct.CurrentConfig.WebhookServer.Security.IntCADir+"/"+intKeyName)
	loghub.Out(3, "Copied certificates from kubernetes secret to all paths!", false)

	//copy if auto-eternity is enabled (these are the same keys as root + int --> keep that in mind)
	if configstruct.CurrentConfig.WebhookServer.Kubernetes.AutoEternity {
		filehandling.CopyAtoB(originDir+"/"+rootKeyName, configstruct.CurrentConfig.WebhookServer.Security.EternityDir+"/"+eternityRootKeyName)
		filehandling.CopyAtoB(originDir+"/"+intKeyName, configstruct.CurrentConfig.WebhookServer.Security.EternityDir+"/"+eternityIntKeyName)
		loghub.Out(3, "Copied eternity keys from kubernetes secret to eternity directory!", false)
	}
}
