package configstruct

import (
	"os"
	"path/filepath"
	"webhook-server/loghub"

	"gopkg.in/yaml.v3"
)

// CurrentConfig stores our config at runtime (can also be updated during runtime)
var CurrentConfig Config

// CurrentConfigPath ... pretty self-explanatory
var CurrentConfigPath string

// Public Chain Base64 string
var BytePublicChain []byte

// Config sets the pattern for our config
type Config struct {
	WebhookServer struct {
		Settings struct {
			Listenport uint16 `yaml:"listenport"`
			DebugLogs  bool   `yaml:"debug-logs"`
		} `yaml:"settings"`
		Security struct {
			RootCADir       string   `yaml:"root-ca-dir"`
			IntCADir        string   `yaml:"int-ca-dir"`
			PubCertPoolDir  string   `yaml:"pub-cert-pool-dir"`
			ServerCertDir   string   `yaml:"server-cert-dir"`
			TempCertDir     string   `yaml:"temp-cert-dir"`
			EternityDir     string   `yaml:"eternity-dir"`
			CAType          string   `yaml:"ca-type"`
			CAStrength      string   `yaml:"ca-strength"`
			DNSAltNames     []string `yaml:"dns-alt-names"`
			IPAltNames      []string `yaml:"ip-alt-names"`
			AllowedAccounts []string `yaml:"allowed-accounts"`
		} `yaml:"security"`
		Kubernetes struct {
			Namespace    string `yaml:"namespace"`
			ConfigMap    string `yaml:"configmap"`
			Secret       string `yaml:"secret"`
			ServiceName  string `yaml:"service-name"`
			AutoEternity bool   `yaml:"auto-eternity"`
		} `yaml:"kubernetes"`
	} `yaml:"webhookserver"`
}

// SetConfig sets the config for central access (and partial updating (port changes still require a restart))
func SetConfig(config Config) {
	CurrentConfig = config
}

// SetConfigPath ... and again (gets called from configchanger.go)
func SetConfigPath(configpath string) {
	CurrentConfigPath = configpath
}

// ConfigWriter only gets called when no config is found to provide a template
func ConfigWriter(file string) {
	template := Config{}
	//set default values
	WriteDefaults(&template)
	//marshal interface to byte array
	output, outputErr := yaml.Marshal(&template)
	if outputErr != nil {
		loghub.Out(1, "YAML marshal error!", false)
		loghub.Err(outputErr)
	}
	//make sure the path exists and then write template to file
	filePath := filepath.Dir(file)
	pErr := os.MkdirAll(filePath, 0755)
	if pErr != nil {
		loghub.Out(1, "Cannot create path"+string(filePath), false)
		loghub.Err(pErr)
	}
	//write data to file
	writeErr := os.WriteFile(file, output, 0755)
	if writeErr != nil {
		loghub.Out(1, "YAML cannot write data to file!", false)
		loghub.Err(writeErr)
	}

	//write config also to CurrentConfig
	CurrentConfig = template
}

// kind of self-explanatory. We set default values since this stupid struct is not able to do this on its own
func WriteDefaults(config *Config) {
	//Settings
	config.WebhookServer.Settings.Listenport = 443
	config.WebhookServer.Settings.DebugLogs = false
	//Security
	config.WebhookServer.Security.RootCADir = "./webhook-server/root-ca-dir"
	config.WebhookServer.Security.IntCADir = "./webhook-server/int-ca-dir"
	config.WebhookServer.Security.PubCertPoolDir = "./webhook-server/pub-cert-pool-dir"
	config.WebhookServer.Security.ServerCertDir = "./webhook-server/server-cert-dir"
	config.WebhookServer.Security.TempCertDir = "./webhook-server/temp-cert-dir"
	config.WebhookServer.Security.EternityDir = "./webhook-server/eternity-dir"
	config.WebhookServer.Security.CAType = "ecdsa"
	config.WebhookServer.Security.CAStrength = "p256"
	config.WebhookServer.Security.DNSAltNames = []string{"webhook-server-svc.default.svc"}
	config.WebhookServer.Security.IPAltNames = []string{"127.0.0.1"}
	config.WebhookServer.Security.AllowedAccounts = []string{"system:serviceaccount:kube-system:default"}
	//Kubernetes
	config.WebhookServer.Kubernetes.Namespace = "default"
	config.WebhookServer.Kubernetes.ConfigMap = "webhook-server-cm"
	config.WebhookServer.Kubernetes.Secret = "webhook-server-sec"
	config.WebhookServer.Kubernetes.ServiceName = "webhook-server-svc"
	config.WebhookServer.Kubernetes.AutoEternity = false
}
