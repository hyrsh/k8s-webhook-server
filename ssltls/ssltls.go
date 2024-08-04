package ssltls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"webhook-server/configstruct"
	"webhook-server/filehandling"
	"webhook-server/k8shub"
	"webhook-server/loghub"
	webhook "webhook-server/utility"
)

/*
	INFORMATION:
	- Signing "Leaf Certificates" from a "Root Certificate Authority" is bad practice
	- "keyUsage" and "extKeyUsage" must be strictly controlled with root/intermediate CAs
	- Signature algorithms should all be forced to SHA512
	- Common names should be human readable and contain a definitive orientation (company name, product name)
	- The golang x509 library cannot do everything openssl does (but it is sufficient, if self-sustained)
	- As soon as "BasicConstraints" are set to "true", there will be a "critical" flag that is responsible for that "yellow exclamation mark" when you "open" the certificate under win10/11 (this is ok and not an error)
*/

/*Common names for x509 DN*/
var authorityCN = "Webhook Server (CA)"
var intermediateCN = "Webhook Server (INTERMEDIATE)"
var serverCN = "Webhook Server (Server)"

/*Organisation for x509 DN*/
var organisation = []string{"Webhook Server"}

/*Get hostname of CA generating instance*/
var tmpHost, _ = os.Hostname()
var host = strings.ToLower(tmpHost)

/*Get IP of CA generating instance for SAN IP (entry is crucial for the X509 implementation)*/
var ip, _ = net.LookupIP(host)

/*IPPool contains all necessary IPs*/
var iPPool []net.IP

/*Root CA paths*/
var rootCert = "/webhook-server-root-ca.crt"
var rootKey = "/webhook-server-root-ca.key"

/*Intermediate CA paths*/
var intCert = "/webhook-server-int-ca.crt"
var intKey = "/webhook-server-int-ca.key"

/*Server cert paths*/
var srvCert = "/webhook-server-srv.crt"
var srvKey = "/webhook-server-srv.key"

/*hash just hashes big integers to get a unique SubjectKeyId from the private keys; SHA1 is ok since we do not need security in this hash*/
func hash(privKey *big.Int) []byte {
	hash := sha1.New()
	hash.Write(privKey.Bytes())
	return hash.Sum(nil)
}

/*Generate random serial number --> must be within range of INT64; field in x509.Certificate.SerialNumber is *big.Int (int64)*/
func serialNumber() *big.Int {
	s, sErr := rand.Int(rand.Reader, big.NewInt(999999999999999999)) //error gets thrown if second parameter equals 0
	if sErr != nil {
		loghub.Out(2, "Certificate serial number generation was invalid (Probability 1 in 999999999999999999)! Restarting your program is enough!", true)
	}
	return s
}

/*
Certificate Authority x509 frame with default data
Update: We do not need that much of information for a CA
*/
var rootCA = x509.Certificate{
	SerialNumber: serialNumber(),
	Subject: pkix.Name{
		CommonName:   authorityCN,
		Organization: organisation,
	},
	NotBefore:             time.Now(),                                                                   //validity starting now
	NotAfter:              time.Now().AddDate(20, 0, 0),                                                 //20 years of validity
	IsCA:                  true,                                                                         //mandatory field for a CA
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign, //mandatory fields for a CA
	BasicConstraintsValid: true,
}

/*Intermediate Certificate Authority*/
var intCA = x509.Certificate{
	SerialNumber: serialNumber(),
	Subject: pkix.Name{
		CommonName:   intermediateCN,
		Organization: organisation,
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
}

/*Server Certificate template*/
var serverCert = x509.Certificate{
	SerialNumber: serialNumber(),
	Subject: pkix.Name{
		CommonName:   serverCN,
		Organization: organisation,
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	BasicConstraintsValid: true,
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	IsCA:                  false,
}

func generateFileName(fileType string, authID string, typeName string) string {
	var name string //full path name
	switch fileType {
	case "crt":
		name = "/" + typeName + "-" + authID + ".crt" //type name e.g. "webhook-server"
	case "key":
		name = "/" + typeName + "-" + authID + ".key" //type name e.g. "webhook-server"
	default:
		loghub.Out(2, "Something went wrong and YOU are the idiot!", true)
	}
	return name
}

/*
CryptInit checks for an empty signing CA dir and creates a one + server certificate
*/
func CryptInit() {
	silent := false
	//dirs
	rootCAdir := configstruct.CurrentConfig.WebhookServer.Security.RootCADir
	intCAdir := configstruct.CurrentConfig.WebhookServer.Security.IntCADir
	srvDir := configstruct.CurrentConfig.WebhookServer.Security.ServerCertDir
	tmpDir := configstruct.CurrentConfig.WebhookServer.Security.TempCertDir
	pubCertDir := configstruct.CurrentConfig.WebhookServer.Security.PubCertPoolDir

	//IP SAN pool
	ipSANpool := getIPfromString(configstruct.CurrentConfig.WebhookServer.Security.IPAltNames)

	//special kubernetes case
	//since the optional secrets create a reference mount within the target directory it is complete BS to work like that
	//we check if we have a respective secret
	//if true we can move the mounted secret files (certs and keys) to the respective directories
	//therefore we do not have to change our certificate workflow (creation and eternity)
	//for our eternity mode the current used certs (in case of an existing secret --> these certs) are used to overwrite the secret
	//if a scale-out (HPA or else) or restart happens we always have the up-to-date certificates
	//the only restriction is a restart of at least one pod within 20 years (which is doable)
	//this should work for the webhook server side within kubernetes up to any scale (but keep race-conditions in mind)

	if k8shub.CheckSecretExists() {
		loghub.Out(3, "You can mount your kubernetes certificates secret to ./kubernetes-certs and set auto-eternity to true", false)
		loghub.Out(3, "The file names within your secret must not change but the values can be your CA + INT CA", false)
		k8shub.MoveK8SSecretCertificates()
	}

	//evaluate and process eternity functions (PKI eternal mode) regularly if running outside of kubernetes
	enterEternity(ipSANpool, tmpDir)

	//check if root CA exists for signing intermediates
	rootCAExist := filehandling.GetPathItems(rootCAdir)
	if rootCAExist > 0 {
		loghub.Out(0, "Root CA directory ("+rootCAdir+") not empty, skipping CA creation!", false)
	} else {
		loghub.Out(0, "Root CA directory ("+rootCAdir+") empty. Creating CA!", false)
		ctype := configstruct.CurrentConfig.WebhookServer.Security.CAType

		//create either ecdsa or rsa certificates
		switch ctype {
		case "ecdsa":
			start := time.Now() //time measurement start
			generateRootCAECDSA()
			end := time.Since(start) //time measurement end
			loghub.Out(3, "Generating root CA took "+end.String(), false)
		case "rsa":
			start := time.Now() //time measurement start
			generateRootCARSA()
			end := time.Since(start) //time measurement end
			loghub.Out(3, "Generating root CA took "+end.String(), false)
		default:
			loghub.Out(2, "Encryption ("+ctype+") not found. Retry with 'rsa' or 'ecdsa'!", true)
		}
	}

	//check if intermediate CA exists for signing servers
	intCAExist := filehandling.GetPathItems(intCAdir)

	if intCAExist > 0 {
		loghub.Out(0, "Intermediate CA directory ("+intCAdir+") not empty, skipping CA creation!", false)
	} else {
		loghub.Out(0, "Intermediate CA directory ("+intCAdir+") empty. Creating CA!", false)
		ctype := configstruct.CurrentConfig.WebhookServer.Security.CAType
		intCA.SerialNumber = serialNumber()

		//set DNS alternative names and IPs
		intCA.DNSNames = configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames
		intCA.IPAddresses = ipSANpool

		//create either ecdsa or rsa certificates
		switch ctype {
		case "ecdsa":
			start := time.Now() //time measurement start
			generateIntCAECDSA(intCAdir, intCert, intKey, silent)
			end := time.Since(start) //time measurement end
			loghub.Out(3, "Generating intermediate CA took "+end.String(), false)
		case "rsa":
			start := time.Now() //time measurement start
			generateIntCARSA(intCAdir, intCert, intKey, silent)
			end := time.Since(start) //time measurement end
			loghub.Out(3, "Generating intermediate CA took "+end.String(), false)
		default:
			loghub.Out(2, "Encryption ("+ctype+") not found. Retry with 'rsa' or 'ecdsa'!", true)
		}
	}

	//at this point we must have a root and intermediate certificate in the respective directories
	intCACert, _ := filehandling.GetCertFiles(intCAdir)
	rootCACert, _ := filehandling.GetCertFiles(rootCAdir)
	filehandling.SingleFileAppend(tmpDir, intCACert, rootCACert, "combined-public-chain", ".crt")
	//setting the public chain to general use in bytes
	pubChainByte := filehandling.ReadFileBytes(tmpDir + "/combined-public-chain.crt")
	configstruct.BytePublicChain = pubChainByte

	//special case since we intertwine certificate authorities for self-sustain
	filehandling.SingleFileAppend(pubCertDir, intCACert, rootCACert, "selfsustain-public-chain", ".crt")

	//always create new server leaf certificate
	loghub.Out(0, "Creating new server (leaf) certificate!", false)
	ctype := configstruct.CurrentConfig.WebhookServer.Security.CAType

	//set DNS alternative names and IPs
	serverCert.DNSNames = configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames
	serverCert.IPAddresses = ipSANpool

	//create either ecdsa or rsa certificates
	startLeaf := time.Now() //time measurement start
	switch ctype {
	case "ecdsa":
		serverECDSA(srvDir, srvCert, srvKey, silent)
	case "rsa":
		serverRSA(srvDir, srvCert, srvKey, silent)
	default:
		loghub.Out(2, "Encryption ("+ctype+") not found. Retry with 'rsa' or 'ecdsa'!", true)
	}
	endLeaf := time.Since(startLeaf) //time measurement end
	loghub.Out(3, "Generating server (leaf) certificate took "+endLeaf.String(), false)

	//Kubernetes part AFTER ALL CERTIFICATES ARE GENERATED OR RENEWED
	//artificial delay of checks to prevent race conditions when replicaSet > 1
	webhook.ReplicaDelay(500, 20) //at least 20ms delay, maximum 500ms delay, no secure seed needed

	sec := configstruct.CurrentConfig.WebhookServer.Kubernetes.Secret
	cm := configstruct.CurrentConfig.WebhookServer.Kubernetes.ConfigMap
	ns := os.Getenv("WHS_K8S_NAMESPACE")
	if !k8shub.UpdateSecret(sec, ns) {
		loghub.Out(2, "Failed to update/create secret", true)
	}
	if !k8shub.UpdateConfigMap(cm, ns) {
		loghub.Out(2, "Failed to update/create configmap", true)
	}
	if !k8shub.CreateTemplateValidationConfig() {
		loghub.Out(2, "Failed to create/update ValidatingWebhookConfiguration template", true)
	}
}

func getIPfromString(ips []string) []net.IP {
	var pool []net.IP
	var tmp net.IP
	for _, v := range ips {
		tmp = net.ParseIP(v)
		pool = append(pool, tmp)
	}
	return pool
}

/*generates an ECDSA certificate authority for signing intermediate CA certificates*/
func generateRootCAECDSA() {
	/*
		CONFIG VALUES
	*/
	eType := configstruct.CurrentConfig.WebhookServer.Security.CAStrength //ecdsa curve strength
	sigCA := configstruct.CurrentConfig.WebhookServer.Security.RootCADir  //directory for signing CA

	/*
		PRIVATE KEY CREATION
	*/
	var ecdsaPRK *ecdsa.PrivateKey //for outer use of switch block
	var edPRK ed25519.PrivateKey   //for outer use of switch block
	var edPUBK ed25519.PublicKey   //for outer use of switch block
	var quantumSafe bool
	switch eType { //private key creation, supported types are P256, P384, P521
	default:
		loghub.Out(2, "Elliptic curve not known or not supported! Try p256, p384, p521 or x25519", true)
	case "p256":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //questionable error handling
	case "p384":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader) //questionable error handling
	case "p521":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader) //questionable error handling
	case "x25519":
		edPUBK, edPRK, _ = ed25519.GenerateKey(rand.Reader) //questionable error handling
		quantumSafe = true
	}

	/*
		If quantum secure keys are generated (x25519? or is ecdsa521 enough) we have to alter our certificate creation process
	*/
	if quantumSafe {
		rootCA.SignatureAlgorithm = x509.SignatureAlgorithm(16) //int 16 = Pure ED25519 --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

		edMarshalledPRK, edMErr := x509.MarshalPKCS8PrivateKey(edPRK)
		if edMErr != nil {
			loghub.Err(edMErr)
		}

		edCert, edCErr := x509.CreateCertificate(rand.Reader, &rootCA, &rootCA, edPUBK, edPRK) //create public part (in memory) of the ecdsa certificate
		if edCErr != nil {
			loghub.Err(edCErr)
		}

		edrCAPublicCert, edrCAPublicCertErr := os.Create(sigCA + rootCert) //open file stream to file (flush memory to file)
		if edrCAPublicCertErr != nil {
			loghub.Out(2, "Public part of Root CA could not be created in: "+sigCA+rootCert, true)
		}

		pem.Encode(edrCAPublicCert, &pem.Block{Type: "CERTIFICATE", Bytes: edCert}) //stream encoded data to file
		edrCAPublicCert.Close()                                                     //close open file handler

		loghub.Out(0, "Public certificate of Root CA created in: "+sigCA+rootCert, false)

		edrCAPrivateCert, edrCAPrivateCertErr := os.OpenFile(sigCA+rootKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) ////this is not just os.Create since we need 0600 for the key
		if edrCAPrivateCertErr != nil {
			loghub.Out(2, "Private key of Root CA could not be created in: "+sigCA+rootKey, true)
		}

		pem.Encode(edrCAPrivateCert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: edMarshalledPRK}) //stream encoded data to file
		edrCAPrivateCert.Close()                                                                 //close open file handler

		loghub.Out(0, "Private key of Root CA created in: "+sigCA+rootKey, false)

		_, checkX509Err := tls.LoadX509KeyPair(sigCA+rootCert, sigCA+rootKey) //checking private and public part of the certificate combined
		if checkX509Err != nil {
			loghub.Err(checkX509Err)
		} else {
			loghub.Out(0, "Certificate valid! (ED25519)", false)
		}
	} else {
		rootCA.SignatureAlgorithm = x509.SignatureAlgorithm(12) //int 12 = SHA512 ECDSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

		/*
			PUBLIC KEY CREATION
		*/
		ecdsaPUK := &ecdsaPRK.PublicKey                                  //public key creation, this is where the magic is happening
		ecdsaMarshalledPRK, empErr := x509.MarshalECPrivateKey(ecdsaPRK) //marshalling private key for PEM encoding (private key file)
		if empErr != nil {
			loghub.Err(empErr)
		}

		/*
			PUBLIC CERTIFICATE CREATION
		*/
		ecdsaCert, crErr := x509.CreateCertificate(rand.Reader, &rootCA, &rootCA, ecdsaPUK, ecdsaPRK) //create public part (in memory) of the ecdsa certificate
		if crErr != nil {
			loghub.Err(crErr)
		}

		/*
			PUBLIC CERTIFICATE WRITE TO FILE
		*/
		rCAPublicCert, rCAPublicCertErr := os.Create(sigCA + rootCert) //open file stream to file (flush memory to file)
		if rCAPublicCertErr != nil {
			loghub.Out(2, "Public part of Root CA could not be created in: "+sigCA+rootCert, true)
		}

		/*
			PEM ENCODING -> CERTIFICATE
		*/
		pem.Encode(rCAPublicCert, &pem.Block{Type: "CERTIFICATE", Bytes: ecdsaCert}) //stream encoded data to file
		rCAPublicCert.Close()                                                        //close open file handler

		loghub.Out(0, "Public certificate of Root CA created in: "+sigCA+rootCert, false)

		/*
			PRIVATE KEY WRITE TO FILE
		*/
		rCAPrivateCert, rCAPrivateCertErr := os.OpenFile(sigCA+rootKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) ////this is not just os.Create since we need 0600 for the key
		if rCAPrivateCertErr != nil {
			loghub.Out(2, "Private key of Root CA could not be created in: "+sigCA+rootKey, true)
		}

		/*
			PEM ENCODING -> PRIVATE KEY
		*/
		pem.Encode(rCAPrivateCert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaMarshalledPRK}) //stream encoded data to file
		rCAPrivateCert.Close()                                                                    //close open file handler

		loghub.Out(0, "Private key of Root CA created in: "+sigCA+rootKey, false)

		/*
			CERTIFICATE VALIDATION
		*/
		loghub.Out(0, "Checking certificate keypair ...", false)
		_, checkX509Err := tls.LoadX509KeyPair(sigCA+rootCert, sigCA+rootKey) //checking private and public part of the certificate combined
		if checkX509Err != nil {
			loghub.Err(checkX509Err)
		} else {
			loghub.Out(0, "Certificate valid! (ECDSA)", false)
		}
	}
}

/*generates an RSA certificate authority for signing intermediate CA certificates*/
func generateRootCARSA() {
	/*
		CONFIG VALUES
	*/
	strKL := configstruct.CurrentConfig.WebhookServer.Security.CAStrength //keylength for RSA
	sigCA := configstruct.CurrentConfig.WebhookServer.Security.RootCADir  //directory for signing CA
	rootCA.SignatureAlgorithm = x509.SignatureAlgorithm(6)                //int 6 = SHA512 RSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	/*
		CHECK PRIVATE KEYLENGTH
	*/
	rsaKeyLength, rsaKeyLengthErr := strconv.Atoi(strKL)
	if rsaKeyLengthErr != nil {
		loghub.Out(2, "RSA keylength not known or not supported! Try 2047, 4096 or 8192", true)
	}
	switch rsaKeyLength { //just let some patterns continue, we limit the available key lengths to ensure a minimum security level
	default:
		loghub.Out(2, "RSA keylength not known or not supported! Try 2047, 4096 or 8192", true)
	case 2048:
		//it's ok
	case 4096:
		//it's ok
	case 8192:
		//it's ok
	}

	/*
		PRIVATE KEY CREATION
	*/
	rCAKeyPrivate, rCAKeyPrivateErr := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if rCAKeyPrivateErr != nil {
		loghub.Out(2, "Generate RSA key failed!", true)
	}

	/*
		PUBLIC KEY CREATION
	*/
	rCAKeyPublic := &rCAKeyPrivate.PublicKey

	/*
		PUBLIC CERTIFICATE CREATION
	*/
	rCACert, rCACertErr := x509.CreateCertificate(rand.Reader, &rootCA, &rootCA, rCAKeyPublic, rCAKeyPrivate)
	if rCACertErr != nil {
		loghub.Out(2, "Root CA creation failed", true)
	}

	/*
		PUBLIC CERTIFICATE WRITE TO FILE
	*/
	rCAPublicCert, rCAPublicCertErr := os.Create(sigCA + rootCert)
	if rCAPublicCertErr != nil {
		loghub.Out(2, "Public part of Root CA could not be created in: "+sigCA+rootCert, true)
	}

	/*
		PEM ENCODING -> CERTIFICATE
	*/
	pem.Encode(rCAPublicCert, &pem.Block{Type: "CERTIFICATE", Bytes: rCACert}) //add PEM certificate block encoding
	rCAPublicCert.Close()

	loghub.Out(0, "Public certificate of Root CA created in: "+sigCA+rootCert, false)

	/*
		PRIVATE KEY WRITE TO FILE
	*/
	rCAPrivateCert, rCAPrivateCertErr := os.OpenFile(sigCA+rootKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) //this is not just os.Create since we need 0600 for the key
	if rCAPrivateCertErr != nil {
		loghub.Out(2, "Private key of Root CA could not be created in: "+sigCA+rootKey, true)
	}
	/*
		PEM ENCODING -> PRIVATE KEY
	*/
	pem.Encode(rCAPrivateCert, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rCAKeyPrivate)}) //add PEM key block encoding
	rCAPrivateCert.Close()

	loghub.Out(0, "Private key of Root CA created in: "+sigCA+rootKey, false)

	/*
		CERTIFICATE VALIDATION
	*/
	loghub.Out(0, "Checking certificate keypair ...", false)
	_, checkX509Err := tls.LoadX509KeyPair(sigCA+rootCert, sigCA+rootKey) //checking private and public part of the certificate combined
	if checkX509Err != nil {
		panic(checkX509Err)
	} else {
		loghub.Out(0, "Certificate valid! (RSA)", false)
	}
}

/*generates an ECDSA certificate authority for signing leaf (server) certificates*/
func generateIntCAECDSA(dir string, crt string, k string, silent bool) {
	//get value from currentConfig
	sigPath := configstruct.CurrentConfig.WebhookServer.Security.RootCADir
	certPath := dir
	eType := configstruct.CurrentConfig.WebhookServer.Security.CAStrength
	intCA.SignatureAlgorithm = x509.SignatureAlgorithm(12) //int 12 = SHA512 ECDSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(sigPath+rootCert, sigPath+rootKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}
	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}
	//error check would be redundant, see generateCertsRSA()

	var ecdsaPRK *ecdsa.PrivateKey //for outer use of switch block
	switch eType {                 //private key creation, supported types are P256, P384, P521
	default:
		loghub.Out(2, "Elliptic curve not known or not supported! Try p256, p384 or p521", true)
	case "p256":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //questionable error handling
	case "p384":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader) //questionable error handling
	case "p521":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader) //questionable error handling
	}
	ecdsaPUK := &ecdsaPRK.PublicKey                                  //public key creation, this is where the magic is happening
	ecdsaMarshalledPRK, empErr := x509.MarshalECPrivateKey(ecdsaPRK) //marshalling private key for PEM encoding (private key file)
	if empErr != nil {
		loghub.Err(empErr)
	}

	intCA.SubjectKeyId = hash(ecdsaPRK.D)
	intCA.AuthorityKeyId = hash(ecdsaPRK.X)

	//sign server certificate
	//1. rand.Reader = io stream
	//2. x509 template (we use our modified serverCert struct)
	//3. parent certificate for signing (CA certificate)
	//4. public key of the signed certificate
	//5. private key of the signing certificate (CA key)
	serverSIGCert, serverSIGCertErr := x509.CreateCertificate(rand.Reader, &intCA, parseCA, ecdsaPUK, caX509.PrivateKey)
	if serverSIGCertErr != nil {
		loghub.Err(serverSIGCertErr)
	}
	//write public server cert
	serverPUCert, serverPUCertErr := os.Create(certPath + crt)
	if serverPUCertErr != nil {
		loghub.Err(serverPUCertErr)
	}
	pem.Encode(serverPUCert, &pem.Block{Type: "CERTIFICATE", Bytes: serverSIGCert})
	serverPUCert.Close() //close file handler
	if !silent {
		loghub.Out(0, "ECDSA public certificate of intermediate CA created in: "+certPath+crt, false)
	}
	//write private server key
	serverPRCert, serverPRCertErr := os.OpenFile(certPath+k, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if serverPRCertErr != nil {
		loghub.Err(serverPRCertErr)
	}
	pem.Encode(serverPRCert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaMarshalledPRK})
	serverPRCert.Close()
	if !silent {
		loghub.Out(0, "ECDSA private key of intermediate CA created in: "+certPath+k, false)
	}
	//Validation
	if !silent {
		loghub.Out(0, "Checking certificate keypair ...", false)
	}
	_, checkX509Err := tls.LoadX509KeyPair(certPath+crt, certPath+k)
	if checkX509Err != nil {
		loghub.Err(checkX509Err)
	} else {
		if !silent {
			loghub.Out(0, "Certificate valid! (ECDSA)", false)
		}
	}
}

/*generates an RSA certificate authority for signing leaf (server) certificates*/
func generateIntCARSA(dir string, crt string, k string, silent bool) {
	//get value from currentConfig
	sigPath := configstruct.CurrentConfig.WebhookServer.Security.RootCADir //path stays always the same
	certPath := dir
	strKL := configstruct.CurrentConfig.WebhookServer.Security.CAStrength //key strength always is given by CA, maybe change to an individual setting if necessary
	intCA.SignatureAlgorithm = x509.SignatureAlgorithm(6)                 //int 6 = SHA512 RSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(sigPath+rootCert, sigPath+rootKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}

	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}

	//error check would be redundant, see generateCertsRSA()
	rsaKeyLength, _ := strconv.Atoi(strKL)

	//generate server private key
	serverPRKey, serverPRKeyErr := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if serverPRKeyErr != nil {
		loghub.Err(serverPRKeyErr)
	}

	//set SubjectKeyId and AuthorityKeyID
	intCA.SubjectKeyId = hash(serverPRKey.D)
	intCA.AuthorityKeyId = hash(serverPRKey.N)

	//generate server public key
	serverPUKey := &serverPRKey.PublicKey

	//sign server certificate
	serverSIGCert, serverSIGCertErr := x509.CreateCertificate(rand.Reader, &intCA, parseCA, serverPUKey, caX509.PrivateKey)
	if serverSIGCertErr != nil {
		loghub.Err(serverSIGCertErr)
	}
	//write public server cert
	serverPUCert, serverPUCertErr := os.Create(certPath + crt)
	if serverPUCertErr != nil {
		loghub.Err(serverPUCertErr)
	}
	pem.Encode(serverPUCert, &pem.Block{Type: "CERTIFICATE", Bytes: serverSIGCert})
	serverPUCert.Close() //close file handler

	if !silent {
		loghub.Out(0, "RSA public certificate of intermediate CA created in: "+certPath+crt, false)
	}

	//write private server key
	serverPRCert, serverPRCertErr := os.OpenFile(certPath+k, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if serverPRCertErr != nil {
		loghub.Err(serverPRCertErr)
	}
	pem.Encode(serverPRCert, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPRKey)})
	serverPRCert.Close()
	if !silent {
		loghub.Out(0, "RSA private key of intermediate CA created in: "+certPath+k, false)
	}

	//Validation
	if !silent {
		loghub.Out(0, "Checking certificate keypair ...", false)
	}
	_, checkX509Err := tls.LoadX509KeyPair(certPath+crt, certPath+k)
	if checkX509Err != nil {
		loghub.Err(checkX509Err)
	} else {
		if !silent {
			loghub.Out(0, "Certificate valid! (RSA)", false)
		}
	}
}

/*serverECDSA generates a signed cert from the intermediate CA*/
func serverECDSA(dir string, crt string, k string, silent bool) {
	//get value from currentConfig
	sigPath := configstruct.CurrentConfig.WebhookServer.Security.IntCADir
	certPath := dir
	eType := configstruct.CurrentConfig.WebhookServer.Security.CAStrength
	serverCert.SignatureAlgorithm = x509.SignatureAlgorithm(12) //int 12 = SHA512 ECDSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(sigPath+intCert, sigPath+intKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}
	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}
	//error check would be redundant, see generateCertsRSA()

	var ecdsaPRK *ecdsa.PrivateKey //for outer use of switch block
	switch eType {                 //private key creation, supported types are P256, P384, P521
	default:
		loghub.Out(2, "Elliptic curve not known or not supported! Try p256, p384 or p521", true)
	case "p256":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //questionable error handling
	case "p384":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader) //questionable error handling
	case "p521":
		ecdsaPRK, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader) //questionable error handling
	}
	ecdsaPUK := &ecdsaPRK.PublicKey                                  //public key creation, this is where the magic is happening
	ecdsaMarshalledPRK, empErr := x509.MarshalECPrivateKey(ecdsaPRK) //marshalling private key for PEM encoding (private key file)
	if empErr != nil {
		loghub.Err(empErr)
	}

	serverCert.SubjectKeyId = hash(ecdsaPRK.D)
	serverCert.AuthorityKeyId = hash(ecdsaPRK.X)

	//sign server certificate
	//1. rand.Reader = io stream
	//2. x509 template (we use our modified serverCert struct)
	//3. parent certificate for signing (CA certificate)
	//4. public key of the signed certificate
	//5. private key of the signing certificate (CA key)
	serverSIGCert, serverSIGCertErr := x509.CreateCertificate(rand.Reader, &serverCert, parseCA, ecdsaPUK, caX509.PrivateKey)
	if serverSIGCertErr != nil {
		loghub.Err(serverSIGCertErr)
	}
	//write public server cert
	serverPUCert, serverPUCertErr := os.Create(certPath + crt)
	if serverPUCertErr != nil {
		loghub.Err(serverPUCertErr)
	}
	pem.Encode(serverPUCert, &pem.Block{Type: "CERTIFICATE", Bytes: serverSIGCert})
	serverPUCert.Close() //close file handler
	if !silent {
		loghub.Out(0, "ECDSA public certificate of server created in: "+certPath+crt, false)
	}
	//write private server key
	serverPRCert, serverPRCertErr := os.OpenFile(certPath+k, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if serverPRCertErr != nil {
		loghub.Err(serverPRCertErr)
	}
	pem.Encode(serverPRCert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaMarshalledPRK})
	serverPRCert.Close()
	if !silent {
		loghub.Out(0, "ECDSA private key of server created in: "+certPath+k, false)
	}
	//Validation
	if !silent {
		loghub.Out(0, "Checking certificate keypair ...", false)
	}
	_, checkX509Err := tls.LoadX509KeyPair(certPath+crt, certPath+k)
	if checkX509Err != nil {
		loghub.Err(checkX509Err)
	} else {
		if !silent {
			loghub.Out(0, "Certificate valid! (ECDSA)", false)
		}
	}
}

/*serverRSA generates a signed cert from the intermediate CA*/
func serverRSA(dir string, crt string, k string, silent bool) {
	//get value from currentConfig
	sigPath := configstruct.CurrentConfig.WebhookServer.Security.IntCADir //path stays always the same
	certPath := dir
	strKL := configstruct.CurrentConfig.WebhookServer.Security.CAStrength //key strength always is given by CA, maybe change to an individual setting if necessary
	serverCert.SignatureAlgorithm = x509.SignatureAlgorithm(6)            //int 6 = SHA512 RSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(sigPath+intCert, sigPath+intKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}

	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}

	//error check would be redundant, see generateCertsRSA()
	rsaKeyLength, _ := strconv.Atoi(strKL)

	//generate server private key
	serverPRKey, serverPRKeyErr := rsa.GenerateKey(rand.Reader, rsaKeyLength)
	if serverPRKeyErr != nil {
		loghub.Err(serverPRKeyErr)
	}

	//set SubjectKeyId and AuthorityKeyID
	serverCert.SubjectKeyId = hash(serverPRKey.D)
	serverCert.AuthorityKeyId = hash(serverPRKey.N)

	//generate server public key
	serverPUKey := &serverPRKey.PublicKey

	//sign server certificate
	serverSIGCert, serverSIGCertErr := x509.CreateCertificate(rand.Reader, &serverCert, parseCA, serverPUKey, caX509.PrivateKey)
	if serverSIGCertErr != nil {
		loghub.Err(serverSIGCertErr)
	}
	//write public server cert
	serverPUCert, serverPUCertErr := os.Create(certPath + crt)
	if serverPUCertErr != nil {
		loghub.Err(serverPUCertErr)
	}
	pem.Encode(serverPUCert, &pem.Block{Type: "CERTIFICATE", Bytes: serverSIGCert})
	serverPUCert.Close() //close file handler

	if !silent {
		loghub.Out(0, "RSA public certificate of server created in: "+certPath+crt, false)
	}

	//write private server key
	serverPRCert, serverPRCertErr := os.OpenFile(certPath+k, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if serverPRCertErr != nil {
		loghub.Err(serverPRCertErr)
	}
	pem.Encode(serverPRCert, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPRKey)})
	serverPRCert.Close()
	if !silent {
		loghub.Out(0, "RSA private key of server created in: "+certPath+k, false)
	}

	//Validation
	if !silent {
		loghub.Out(0, "Checking certificate keypair ...", false)
	}
	_, checkX509Err := tls.LoadX509KeyPair(certPath+crt, certPath+k)
	if checkX509Err != nil {
		loghub.Err(checkX509Err)
	} else {
		if !silent {
			loghub.Out(0, "Certificate valid! (RSA)", false)
		}
	}
}
