package configchanger

import (
	"os"
	"webhook-server/configstruct"
	"webhook-server/loghub"

	"gopkg.in/yaml.v3"
)

// this is a writing operation that flushes the current runtime data (CurrentConfig struct in configstruct.go) to the configfile
// everything is marshalled in yaml
func UpdateConfig(info string) {
	//path to current config file
	cfgfile := configstruct.CurrentConfigPath

	//marshal interface to byte array (updated config)
	output, outputErr := yaml.Marshal(configstruct.CurrentConfig)
	if outputErr != nil {
		loghub.Err(outputErr)
	}
	//write updated data to file
	writeErr := os.WriteFile(cfgfile, output, 0755)
	if writeErr != nil {
		loghub.Err(writeErr)
	}
	loghub.Out(0, "Updated config! ("+info+")", false)
}
