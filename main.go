//On Windows
//$env:CGO_ENABLED = 1; go build -ldflags='-s -w -extldflags "-static"' main.go

//On Windows cross-compile for Linux
//$env:CGO_ENABLED = 0; $env:GOOS = "linux"; $env:GOARCH = "amd64"; go build -o core_blh_linux_x86_64 -ldflags='-s -w -extldflags "-static"' main.go

//On Linux (important for docker image building with "FROM scratch")
//go build -a -tags netgo --ldflags '-extldflags "-static"'

//packed with
//upx --best webhook-server.exe (Windows)
//or
//upx --best webhook-server (Linux)
//brute compression throws a false positive with Windows Defender -.-"

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"webhook-server/checkconfig"
	"webhook-server/configstruct"
	"webhook-server/loghub"
	"webhook-server/slurper"
	"webhook-server/ssltls"
	w1 "webhook-server/utility"

	v1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	// TODO: try this library to see if it generates correct json patch
	// https://github.com/mattbaird/jsonpatch
)

const Version string = "1.1"

var (
	certFile string = "/webhook-server/server-cert-dir/webhook-server-srv.crt"
	keyFile  string = "/webhook-server/server-cert-dir/webhook-server-srv.key"
)

// admitv1beta1Func handles a v1beta1 admission
type admitv1beta1Func func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

// admitv1beta1Func handles a v1 admission
type admitv1Func func(v1.AdmissionReview) *v1.AdmissionResponse

// admitHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type admitHandler struct {
	v1beta1 admitv1beta1Func
	v1      admitv1Func
}

func newDelegateToV1AdmitHandler(f admitv1Func) admitHandler {
	return admitHandler{
		v1beta1: delegateV1beta1AdmitToV1(f),
		v1:      f,
	}
}

func delegateV1beta1AdmitToV1(f admitv1Func) admitv1beta1Func {
	return func(review v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
		in := v1.AdmissionReview{Request: w1.ConvertAdmissionRequestToV1(review.Request)}
		out := f(in)
		return w1.ConvertAdmissionResponseToV1beta1(out)
	}
}

// serve handles the http portion of a request prior to handing to an admit
// function
func serve(w http.ResponseWriter, r *http.Request, admit admitHandler) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Println("Content-Type is not application/json")
		return
	}

	deserializer := w1.Codecs.UniversalDeserializer()
	obj, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		msg := fmt.Sprintf("Request could not be decoded: %v", err)
		log.Println("Could not decode request!", err)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case v1beta1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1beta1.AdmissionReview)
		if !ok {
			log.Println("Expected v1beta1.AdmissionReview but got:", obj)
			return
		}
		responseAdmissionReview := &v1beta1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1beta1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
		requestedAdmissionReview, ok := obj.(*v1.AdmissionReview)
		if !ok {
			log.Println("Expected v1.AdmissionReview but got:", obj)
			return
		}
		responseAdmissionReview := &v1.AdmissionReview{}
		responseAdmissionReview.SetGroupVersionKind(*gvk)
		responseAdmissionReview.Response = admit.v1(*requestedAdmissionReview)
		responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		responseObj = responseAdmissionReview
	default:
		msg := fmt.Sprintf("Unsupported group version kind: %v", gvk)
		log.Println("Unsupported group version kind:", gvk)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	//klog.V(2).Info(fmt.Sprintf("sending response: %v", responseObj))
	respBytes, err := json.Marshal(responseObj)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		log.Println(err)
	}
}

func serveUserDeny(w http.ResponseWriter, r *http.Request) {
	serve(w, r, newDelegateToV1AdmitHandler(w1.UserDeny))
}

func serveAudit(w http.ResponseWriter, r *http.Request) {
	serve(w, r, newDelegateToV1AdmitHandler(w1.Audit))
}

func main() {
	loghub.Out(0, "Webhook Server Node v"+Version, false)

	//cli flags for config file path
	configPath := flag.String("config", "./config.yml", "Path to config file")
	flag.Parse()

	//read config at path or create a default template
	slurper.Init(*configPath)

	//checkconfig
	checkconfig.Init()

	//add kubernetes service name to certificate pool
	checkconfig.SetDNSAltNames()

	//generate certificates
	ssltls.CryptInit()

	//set http handler certificate paths (you dont need to worry it is always static) --> dont touch
	config := w1.Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	http.HandleFunc("/user-audit", serveAudit)
	http.HandleFunc("/user-deny", serveUserDeny)
	http.HandleFunc("/readyz", func(w http.ResponseWriter, req *http.Request) { w.Write([]byte("ok")) })
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", configstruct.CurrentConfig.WebhookServer.Settings.Listenport),
		TLSConfig: w1.ConfigTLS(config),
	}
	loghub.Out(0, "Available paths:", false)
	loghub.Out(0, "/user-audit  print user activity in logs for respective VWC", false)
	loghub.Out(0, "/user-deny   denies all users except allowed accounts with respective VWC", false)
	loghub.Out(0, "/readyz      general OK request (no validation)", false)
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
