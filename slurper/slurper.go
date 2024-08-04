package slurper

import (
	"os"
	"webhook-server/configstruct"
	"webhook-server/filehandling"
	"webhook-server/k8shub"
	"webhook-server/loghub"

	"gopkg.in/yaml.v3"
)

// Init just consumes a path to a file
func Init(file string) {
	if filehandling.StatFile(file) {
		loghub.Out(0, "Config found at "+file, false)
	} else {
		loghub.Out(1, "Config not found. Creating template configmap!", false)
		K8SConfigWriter(file)
		loghub.Out(1, "Adjust configmap "+configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap+" and mount it to /config.yml", false)
		loghub.Out(1, "Restart the deployment afterwards!", false)
	}
	loadConfig(file)
}

// reload config from local file mount
// this is necessary during runtime if we have scaled deployments in kubernetes with auto-updated values from other instances
// also works on bare-metal if multiple instances use the same configs and have RWX permissions
func ReloadConfig() {
	file := configstruct.CurrentConfigPath
	loadConfig(file)
	loghub.Out(0, "Reloaded config", false)
}

func loadConfig(file string) {
	configData, configError := os.ReadFile(file)
	if configError != nil {
		loghub.Out(1, "Could not read config file!", false)
		loghub.Err(configError)
	}
	var rawYAML configstruct.Config
	ymlErr := yaml.Unmarshal(configData, &rawYAML)
	if ymlErr != nil {
		loghub.Out(1, "Unmarshal error!", false)
		loghub.Err(ymlErr)
	}
	configstruct.SetConfig(rawYAML)
	configstruct.SetConfigPath(file)

	//set debug true/false ... dont ask it is stupid, I know
	loghub.SetDebug(configstruct.CurrentConfig.WebhookServer.Settings.DebugLogs)

	loghub.Out(3, "Loaded config into memory!", false)
}

func K8SConfigWriter(file string) {
	template := configstruct.Config{}
	//set default values
	configstruct.WriteDefaults(&template)
	//marshal interface to byte array
	_, outputErr := yaml.Marshal(&template)
	if outputErr != nil {
		loghub.Out(1, "YAML marshal error!", false)
		loghub.Err(outputErr)
	}

	//write config also to CurrentConfig
	configstruct.CurrentConfig = template
	k8shub.UpdateConfigMap(template.WebhookServer.Kubernetes.ConfigMap, template.WebhookServer.Kubernetes.Namespace)
}
