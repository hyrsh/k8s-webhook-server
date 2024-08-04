package loghub

import (
	"log"
)

var debugEnabled = false

func SetDebug(dbgflag bool) {
	debugEnabled = dbgflag
}

// Out will be handy to standardize logging
func Out(level int16, msg string, fatality bool) {
	var output string
	switch level {
	case 0:
		output = "[INFO]  " + msg
	case 1:
		output = "[WARN]  " + msg
	case 2:
		output = "[ERROR] " + msg
	case 3:
		if debugEnabled {
			output = "[DEBUG] " + msg
		}
	case 4:
		output = "[GRPC]  " + msg
	default:
		log.Fatal("You should never see this. Fuck off and fix your code!")
	}
	if fatality {
		log.Fatal(output)
	}
	if output != "" {
		log.Println(output)
	}
}

// Err is just a wrapper until I find something else
func Err(msg error) {
	log.Fatal("[ERROR] ", msg)
}
