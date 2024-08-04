package webhook

import (
	"crypto/tls"
	"math/rand/v2"
	"strconv"
	"time"

	"k8s.io/klog"
)

// Config contains the server (the webhook) cert and key.
type Config struct {
	CertFile string
	KeyFile  string
}

func ConfigTLS(config Config) *tls.Config {
	sCert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		klog.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sCert},
	}
}

func ReplicaDelay(max, min int) {
	delay := rand.IntN(max-min) + min
	parsedDelay, err := time.ParseDuration(strconv.Itoa(delay) + "ms")
	if err != nil {
		time.Sleep(1 * time.Second)
	} else {
		time.Sleep(parsedDelay)
	}
}
