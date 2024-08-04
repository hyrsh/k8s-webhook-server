package ssltls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"strings"
	"time"
	"webhook-server/configstruct"
	"webhook-server/filehandling"
	"webhook-server/loghub"
)

var renewedRootCert string = "/webhook-server-root-ca.crt"
var renewedRootKey string = "/webhook-server-root-ca.key"
var renewedIntCert string = "/webhook-server-int-ca.crt"
var renewedIntKey string = "/webhook-server-int-ca.key"

func enterEternity(ipSANpool []net.IP, tmpDir string) {
	//still WIP but IF WE WANT to renew, these are the parameters for the keys
	renew, keyFilePathRoot, keyFilePathInt, keyTypeRoot, keyTypeInt := renewCATrigger()

	//react to renewal trigger
	if renew {
		//set DNS alternative names and IPs (only necessary for intermediate certificates)
		intCA.DNSNames = configstruct.CurrentConfig.WebhookServer.Security.DNSAltNames
		intCA.IPAddresses = ipSANpool

		/*
			Root renewal
		*/
		start := time.Now() //time measurement start
		switch keyTypeRoot {
		case "ecdsa":
			if renewRootCAECDSA(keyFilePathRoot, tmpDir) {

			}
		case "rsa":
			if renewRootCARSA(keyFilePathRoot, tmpDir) {

			}
		default:
		}
		end := time.Since(start) //time measurement end
		loghub.Out(3, "[~] Renewing root CA took "+end.String(), false)

		/*
			Intermediate renewal
		*/
		startInt := time.Now() //time measurement start
		switch keyTypeInt {
		case "ecdsa":
			if renewIntCAECDSA(keyFilePathInt, tmpDir) {

			}
		case "rsa":
			if renewIntCARSA(keyFilePathInt, tmpDir) {

			}
		default:

		}
		endInt := time.Since(startInt) //time measurement end
		loghub.Out(3, "[~] Renewing intermediate CA took "+endInt.String(), false)

		/*
			FEATURE --> rotating and/or S3 export:
			As long as we are in a development we just overwrite the old certificates
		*/
		overwriteCertificates() //temporary default
		loghub.Out(0, "|", false)
		loghub.Out(0, "[-'*+-.,_ ETERNITY KEYS OK _,.-+*'-]", false) //only after successful parsing we can say that this will work

	} else {
		loghub.Out(3, "Eternity mode could not be entered!", false)
	}
}

/*
Renew CA Trigger
Evaluate if we can start the renewal itself
*/
func renewCATrigger() (bool, string, string, string, string) {
	//INFORMATION
	/*
		The renewal is kind of not what I expected.

		There is a possibility to renew the expiry date on a certificate authority (and intermediate authority) by reusing the existing keys (public+private).
		The distribution of a new certificate also changes due to this strange behaviour. We have to distribute the full public chain (in the right order)

		There is another thing that could be dangerous if building big PKIs which is path building (we may have to re-think our serial number generation or setting):
		--> see https://www.rfc-editor.org/rfc/rfc4158#page-15
		For our small PKI cells I do not think that a path building problem will arise.

		For now I implemented the following:

		1. If there are keys for root and intermediate certificates in the eternity directory --> trigger renewal of them
		2. The keys get checked and parsed for key and security compatibility
		3. The current certificates get resigned by themselves to extend their expiry date
		4. The signing of the leaf certificates does not deviate from the default process (it already happens constantly)
	*/

	//this may seem like a double check but I am stupid enough to do it
	rootCAdir := configstruct.CurrentConfig.WebhookServer.Security.RootCADir
	intCAdir := configstruct.CurrentConfig.WebhookServer.Security.IntCADir
	rootCAExist := filehandling.GetPathItems(rootCAdir)
	if rootCAExist <= 0 {
		loghub.Out(1, "Root CA directory ("+rootCAdir+") empty, renewal of PKI not possible!", false)
		return false, "", "", "", ""
	}

	intCAExist := filehandling.GetPathItems(intCAdir)
	if intCAExist <= 0 {
		loghub.Out(1, "Intermediate CA directory ("+intCAdir+") empty, renewal of PKI not possible!", false)
		return false, "", "", "", ""
	}

	/*
		Key template name: eternity_root_ecdsa_p256.key
		--> prefix:      eternity
		--> authority:   root
		--> placeholder: _
		--> type:        ecdsa //must match supported types and previous type
		--> strength:    p256  //must match supported strenghts and previous strengths
	*/
	//dir to check for key
	dir := configstruct.CurrentConfig.WebhookServer.Security.EternityDir
	amount := filehandling.GetPathItems(dir) //see if we have something

	if amount == 2 { //we dictate to have only two keys in here
		rootKeyFile, intKeyFile := filehandling.GetPKIFileNames(dir)
		if rootKeyFile == "" && intKeyFile == "" {
			return false, "", "", "", ""
		}

		loghub.Out(0, "[_,.-+*'- CHECKING ETERNITY KEYS -'*+-.,_]", false) //fancy
		loghub.Out(0, "|", false)                                          //fancy

		parseStateRoot, keyTypeRoot := parseEternityKey(rootKeyFile) //see if we can parse the file
		if !parseStateRoot {                                         //parsing success?
			return false, "", "", "", ""
		}
		parseStateInt, keyTypeInt := parseEternityKey(intKeyFile) //see if we can parse the file
		if !parseStateInt {                                       //parsing success?
			return false, "", "", "", ""
		}
		//good case, all parsing was successful and both keys were found
		keyFilePathRoot := dir + "/" + rootKeyFile //complete path to file (necessary on later functions)
		keyFilePathInt := dir + "/" + intKeyFile   //complete path to file (necessary on later functions)
		return true, keyFilePathRoot, keyFilePathInt, keyTypeRoot, keyTypeInt
	} else {
		loghub.Out(3, "None or more than 2x keys (root, intermediate) were found. Not renewing PKI.", false)
		return false, "", "", "", ""
	}
}

// this is necessary since we need some information about the key origin to keep security on the same level
func parseEternityKey(keyFileName string) (bool, string) {
	var keyType string //parsed type and strength
	placeholder := "_" //placeholder we dictate

	//see if file is ended with ".something", this is kinda stupid but file endings have their meaning
	//index 0 holds our parsable part
	stripFiletype := strings.Split(keyFileName, ".")

	if len(stripFiletype) <= 0 {
		loghub.Out(2, "Eternity key file has no default file ending \".key\"!", false)
		return false, ""
	}
	loghub.Out(0, "[~] Eternity key file: "+keyFileName, false) //see what we got

	//parse the first split
	fileNameParts := strings.Split(stripFiletype[0], placeholder) //split again with placeholder

	if len(fileNameParts) != 4 { //it is crucial to have "prefix", "authority", "type", "strength", otherwise fu
		loghub.Out(2, "Eternity key file has not enough parsable parts! (e.g. eternity_ecdsa_p256.key)", false)
		return false, ""
	} else {
		loghub.Out(0, "[~] Eternity prefix:    "+fileNameParts[0], false) //the user must rename the file (hopefully with great awareness in mind)
		loghub.Out(0, "[~] Eternity authority: "+fileNameParts[1], false)
		loghub.Out(0, "[~] Eternity key type:  "+fileNameParts[2], false)
		loghub.Out(0, "[~] Eternity strength:  "+fileNameParts[3], false)
		switch fileNameParts[0] { //index 0 is our prefix
		case "eternity":
			switch fileNameParts[1] { //index 1 is our authority
			case "root", "int":
				switch fileNameParts[2] { //index 2 is our key type
				case "rsa":
					keyType = "rsa"
					switch fileNameParts[3] { //index 3 is our key strength
					case "2048":
						//ok, technical parsing happens later
					case "4096":
						//ok, technical parsing happens later
					case "8192":
						//ok, technical parsing happens later
					default:
						loghub.Out(2, "Eternity key file has no parsable RSA strength! (e.g. 2048, 4096, 8192)", false)
						return false, ""
					}
				case "ecdsa":
					keyType = "ecdsa"
					switch fileNameParts[3] { //index 2 is our key strength
					case "p256":
						//ok, technical parsing happens later
					case "p384":
						//ok, technical parsing happens later
					case "p521":
						//ok, technical parsing happens later
					default:
						loghub.Out(2, "Eternity key file has no parsable ECDSA strength! (e.g. p256, p384, p521)", false)
						return false, ""
					}
				default:
					loghub.Out(2, "Eternity key file has no parsable type! (e.g. ecdsa or rsa)", false)
					return false, ""
				}
			default:
				return false, ""
			}
		default:
			return false, ""
		}
	}
	return true, keyType //return if successful, key strength must only be checked but not returned; a faulty key will fail in parsing when it comes to certificate creation
}

/*renews an ECDSA certificate authority for signing intermediate CA certificates*/
func renewRootCAECDSA(fullKeyPath string, targetDir string) bool {
	/*
		CONFIG VALUES
	*/
	oldRootCADir := configstruct.CurrentConfig.WebhookServer.Security.RootCADir
	sigCA := targetDir                                      //directory to write the files to
	rootCA.SignatureAlgorithm = x509.SignatureAlgorithm(12) //int 12 = SHA512 ECDSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(oldRootCADir+rootCert, oldRootCADir+rootKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}

	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}

	parseCA.NotAfter = time.Now().AddDate(20, 0, 0)

	/*
		PRIVATE KEY LOAD
		PEM encryption/decryption (x509.DecryptPEMBlock) is deprecated but we use it as encoding so I hope there is nothing to worry about
	*/
	var PEMErr error
	keyBytes := filehandling.ReadFileBytes(fullKeyPath) //load bytes of key file
	block, _ := pem.Decode(keyBytes)                    //decode PEM encoding on key to get raw data
	blockBytes := block.Bytes                           //get key bytes
	_, ok := block.Headers["DEK-Info"]                  //set DEK Info headers
	if ok {
		blockBytes, PEMErr = x509.DecryptPEMBlock(block, nil) //DEK Info headers + key bytes
		if PEMErr != nil {
			loghub.Err(PEMErr)
		}
	}
	ecdsaPRK, ecdsaParseErr := x509.ParseECPrivateKey(blockBytes) //parse bytes to key
	if ecdsaParseErr != nil {
		loghub.Out(2, "Cannot parse root eternity key!", false)
		loghub.Err(ecdsaParseErr)
	}
	loghub.Out(0, "[~] Root eternity key successfully parsed!", false)

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
	ecdsaCert, crErr := x509.CreateCertificate(rand.Reader, parseCA, parseCA, ecdsaPUK, ecdsaPRK) //create public part (in memory) of the ecdsa certificate
	if crErr != nil {
		loghub.Err(crErr)
		loghub.Out(2, "[~] Root CA renewal failed", true)
	}

	/*
		PUBLIC CERTIFICATE WRITE TO FILE
	*/
	rCAPublicCert, rCAPublicCertErr := os.Create(sigCA + renewedRootCert) //open file stream to file (flush memory to file)
	if rCAPublicCertErr != nil {
		loghub.Out(2, "Renewal of public part of Root CA could not be done for: "+sigCA+renewedRootCert, true)
	}

	/*
		PEM ENCODING -> CERTIFICATE
	*/
	pem.Encode(rCAPublicCert, &pem.Block{Type: "CERTIFICATE", Bytes: ecdsaCert}) //stream encoded data to file
	rCAPublicCert.Close()                                                        //close open file handler

	loghub.Out(0, "Renewed public certificate of Root CA created in: "+sigCA+renewedRootCert, false)

	/*
		PRIVATE KEY WRITE TO FILE
	*/
	rCAPrivateCert, rCAPrivateCertErr := os.OpenFile(sigCA+renewedRootKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) ////this is not just os.Create since we need 0600 for the key
	if rCAPrivateCertErr != nil {
		loghub.Out(2, "Eternity key could not be copied to: "+sigCA+renewedRootKey, true)
	}

	/*
		PEM ENCODING -> PRIVATE KEY
	*/
	pem.Encode(rCAPrivateCert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaMarshalledPRK}) //stream encoded data to file
	rCAPrivateCert.Close()                                                                    //close open file handler

	loghub.Out(0, "Eternity key copied to: "+sigCA+renewedRootKey, false)

	/*
		CERTIFICATE VALIDATION
	*/
	loghub.Out(0, "Checking renewed certificate keypair ...", false)
	_, checkX509Err := tls.LoadX509KeyPair(sigCA+renewedRootCert, sigCA+renewedRootKey) //checking private and public part of the certificate combined
	if checkX509Err != nil {
		loghub.Err(checkX509Err)
	} else {
		loghub.Out(0, "Renewed certificate valid! (ECDSA)", false)
	}
	filehandling.CertCombiner(sigCA, renewedRootCert, renewedRootKey, "renewed-root")
	return true //there are already a lot of checks beforehand, if we manage to get to this point, everything is ok
}

/*renews an RSA certificate authority for signing intermediate CA certificates*/
func renewRootCARSA(fullKeyPath string, targetDir string) bool {
	/*
		CONFIG VALUES
	*/
	oldRootCADir := configstruct.CurrentConfig.WebhookServer.Security.RootCADir
	sigCA := targetDir                                     //directory for signing CA
	rootCA.SignatureAlgorithm = x509.SignatureAlgorithm(6) //int 6 = SHA512 RSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(oldRootCADir+rootCert, oldRootCADir+rootKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}

	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}

	parseCA.NotAfter = time.Now().AddDate(20, 0, 0)

	/*
		PRIVATE KEY LOAD
		PEM encryption/decryption is deprecated but we use it as encoding so I hope there is nothing to worry about
	*/
	var PEMErr error
	keyBytes := filehandling.ReadFileBytes(fullKeyPath) //load bytes of key file
	block, _ := pem.Decode(keyBytes)                    //decode PEM encoding on key to get raw data
	blockBytes := block.Bytes                           //get key bytes
	_, ok := block.Headers["DEK-Info"]                  //set DEK Info headers
	if ok {
		blockBytes, PEMErr = x509.DecryptPEMBlock(block, nil) //DEK Info headers + key bytes
		if PEMErr != nil {
			loghub.Err(PEMErr)
		}
	}
	rCAKeyPrivate, rCAKeyPrivateErr := x509.ParsePKCS1PrivateKey(blockBytes) //parse bytes to key
	if rCAKeyPrivateErr != nil {
		loghub.Out(2, "[~] Cannot parse eternity key!", false)
		loghub.Err(rCAKeyPrivateErr)
	}
	loghub.Out(0, "[~] Root eternity key successfully parsed!", false)

	/*
		PUBLIC KEY CREATION
	*/
	rCAKeyPublic := &rCAKeyPrivate.PublicKey

	/*
		PUBLIC CERTIFICATE CREATION
	*/
	rCACert, rCACertErr := x509.CreateCertificate(rand.Reader, parseCA, parseCA, rCAKeyPublic, rCAKeyPrivate)
	if rCACertErr != nil {
		loghub.Err(rCACertErr)
		loghub.Out(2, "[~] Root CA renewal failed", true)
	}

	/*
		PUBLIC CERTIFICATE WRITE TO FILE
	*/
	rCAPublicCert, rCAPublicCertErr := os.Create(sigCA + renewedRootCert)
	if rCAPublicCertErr != nil {
		loghub.Out(2, "[~] Renewal of public part of Root CA could not be done for: "+sigCA+renewedRootCert, true)
	}

	/*
		PEM ENCODING -> CERTIFICATE
	*/
	pem.Encode(rCAPublicCert, &pem.Block{Type: "CERTIFICATE", Bytes: rCACert}) //add PEM certificate block encoding
	rCAPublicCert.Close()

	loghub.Out(0, "[~] Renewed public certificate of Root CA created in: "+sigCA+renewedRootCert, false)

	/*
		PRIVATE KEY WRITE TO FILE
	*/
	rCAPrivateCert, rCAPrivateCertErr := os.OpenFile(sigCA+renewedRootKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) //this is not just os.Create since we need 0600 for the key
	if rCAPrivateCertErr != nil {
		loghub.Out(2, "[~] Root eternity key could not be copied to: "+sigCA+renewedRootKey, true)
	}
	/*
		PEM ENCODING -> PRIVATE KEY
	*/
	pem.Encode(rCAPrivateCert, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rCAKeyPrivate)}) //add PEM key block encoding
	rCAPrivateCert.Close()

	loghub.Out(0, "[~] Root eternity key copied to: "+sigCA+renewedRootKey, false)

	/*
		CERTIFICATE VALIDATION
	*/
	loghub.Out(0, "[~] Checking renewed certificate keypair ...", false)
	_, checkX509Err := tls.LoadX509KeyPair(sigCA+renewedRootCert, sigCA+renewedRootKey) //checking private and public part of the certificate combined
	if checkX509Err != nil {
		panic(checkX509Err)
	} else {
		loghub.Out(0, "[~] Renewed root certificate valid! (RSA)", false)
	}
	//filehandling.CertCombiner(sigCA, renewedRootCert, renewedRootKey, "renewed-root")
	filehandling.SingleFileAppend(sigCA, sigCA+renewedRootCert, sigCA+renewedRootKey, "combined-renewed-root", ".pem")
	return true //there are already a lot of checks beforehand, if we manage to get to this point, everything is ok
}

/*renews an ECDSA certificate authority for signing server certificates*/
func renewIntCAECDSA(fullKeyPath string, targetDir string) bool {
	/*
		CONFIG VALUES
	*/
	oldIntCADir := configstruct.CurrentConfig.WebhookServer.Security.IntCADir
	sigCA := targetDir
	intCA.SignatureAlgorithm = x509.SignatureAlgorithm(12) //int 12 = SHA512 ECDSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(sigCA+renewedRootCert, sigCA+renewedRootKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}

	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}

	//load previous generated INT CA
	intX509, intX509Err := tls.LoadX509KeyPair(oldIntCADir+intCert, oldIntCADir+intKey)
	if intX509Err != nil {
		loghub.Err(intX509Err)
	}

	//parse loaded INT CA
	parseInt, parseIntErr := x509.ParseCertificate(intX509.Certificate[0])
	if parseIntErr != nil {
		loghub.Err(parseIntErr)
	}

	parseInt.NotAfter = time.Now().AddDate(10, 0, 0)

	/*
		PRIVATE KEY LOAD
		PEM encryption/decryption is deprecated but we use it as encoding so I hope there is nothing to worry about
	*/
	var PEMErr error
	keyBytes := filehandling.ReadFileBytes(fullKeyPath) //load bytes of key file
	block, _ := pem.Decode(keyBytes)                    //decode PEM encoding on key to get raw data
	blockBytes := block.Bytes                           //get key bytes
	_, ok := block.Headers["DEK-Info"]                  //set DEK Info headers
	if ok {
		blockBytes, PEMErr = x509.DecryptPEMBlock(block, nil) //DEK Info headers + key bytes
		if PEMErr != nil {
			loghub.Err(PEMErr)
		}
	}
	ecdsaPRK, ecdsaParseErr := x509.ParseECPrivateKey(blockBytes) //parse bytes to key
	if ecdsaParseErr != nil {
		loghub.Out(2, "Cannot parse root eternity key!", false)
		loghub.Err(ecdsaParseErr)
	}
	loghub.Out(0, "[~] Intermediate eternity key successfully parsed!", false)

	/*
		PUBLIC KEY CREATION
	*/
	ecdsaPUK := &ecdsaPRK.PublicKey //public key creation, this is where the magic is happening
	//marshalling is necessary in opposition to RSA, since the x509.MarshalECPrivateKey(...) has more return values
	ecdsaMarshalledPRK, empErr := x509.MarshalECPrivateKey(ecdsaPRK) //marshalling private key for PEM encoding (private key file)
	if empErr != nil {
		loghub.Err(empErr)
	}

	/*
		PUBLIC CERTIFICATE CREATION
	*/
	serverSIGCert, serverSIGCertErr := x509.CreateCertificate(rand.Reader, parseInt, parseCA, ecdsaPUK, caX509.PrivateKey)
	if serverSIGCertErr != nil {
		loghub.Err(serverSIGCertErr)
	}

	/*
		PUBLIC CERTIFICATE WRITE TO FILE
	*/
	serverPUCert, serverPUCertErr := os.Create(sigCA + renewedIntCert)
	if serverPUCertErr != nil {
		loghub.Err(serverPUCertErr)
	}

	/*
		PEM ENCODING -> CERTIFICATE
	*/
	pem.Encode(serverPUCert, &pem.Block{Type: "CERTIFICATE", Bytes: serverSIGCert})
	serverPUCert.Close() //close file handler

	/*
		PRIVATE KEY WRITE TO FILE
	*/
	serverPRCert, serverPRCertErr := os.OpenFile(sigCA+renewedIntKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if serverPRCertErr != nil {
		loghub.Err(serverPRCertErr)
	}

	/*
		PEM ENCODING -> PRIVATE KEY
	*/
	pem.Encode(serverPRCert, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecdsaMarshalledPRK})
	serverPRCert.Close()

	loghub.Out(0, "[~] Intermediate eternity key copied to: "+sigCA+renewedIntKey, false)

	/*
		CERTIFICATE VALIDATION
	*/
	loghub.Out(0, "[~] Checking renewed intermediate certificate keypair ...", false)
	_, checkX509Err := tls.LoadX509KeyPair(sigCA+renewedIntCert, sigCA+renewedIntKey) //checking private and public part of the certificate combined
	if checkX509Err != nil {
		panic(checkX509Err)
	} else {
		loghub.Out(0, "[~] Renewed intermediate certificate valid! (RSA)", false)
	}
	//filehandling.CertCombiner(certPath, crt, k, "intermediate")
	filehandling.SingleFileAppend(sigCA, sigCA+renewedIntCert, sigCA+renewedIntKey, "combined-renewed-intermediate", ".pem")
	return true //there are already a lot of checks beforehand, if we manage to get to this point, everything is ok
}

/*renews an RSA certificate authority for signing server certificates*/
func renewIntCARSA(fullKeyPath string, targetDir string) bool {
	/*
		CONFIG VALUES
	*/
	oldIntCADir := configstruct.CurrentConfig.WebhookServer.Security.IntCADir
	sigCA := targetDir                                    //directory for signing CA
	intCA.SignatureAlgorithm = x509.SignatureAlgorithm(6) //int 6 = SHA512 RSA --> see https://pkg.go.dev/crypto/x509#SignatureAlgorithm

	//load previous generated CA
	caX509, caX509Err := tls.LoadX509KeyPair(sigCA+renewedRootCert, sigCA+renewedRootKey)
	if caX509Err != nil {
		loghub.Err(caX509Err)
	}

	//parse loaded CA
	parseCA, parseCAErr := x509.ParseCertificate(caX509.Certificate[0])
	if parseCAErr != nil {
		loghub.Err(parseCAErr)
	}

	//load previous generated INT CA
	intX509, intX509Err := tls.LoadX509KeyPair(oldIntCADir+intCert, oldIntCADir+intKey)
	if intX509Err != nil {
		loghub.Err(intX509Err)
	}

	//parse loaded INT CA
	parseInt, parseIntErr := x509.ParseCertificate(intX509.Certificate[0])
	if parseIntErr != nil {
		loghub.Err(parseIntErr)
	}

	parseInt.NotAfter = time.Now().AddDate(10, 0, 0)

	/*
		PRIVATE KEY LOAD
		PEM encryption/decryption is deprecated but we use it as encoding so I hope there is nothing to worry about
	*/
	var PEMErr error
	keyBytes := filehandling.ReadFileBytes(fullKeyPath) //load bytes of key file
	block, _ := pem.Decode(keyBytes)                    //decode PEM encoding on key to get raw data
	blockBytes := block.Bytes                           //get key bytes
	_, ok := block.Headers["DEK-Info"]                  //set DEK Info headers
	if ok {
		blockBytes, PEMErr = x509.DecryptPEMBlock(block, nil) //DEK Info headers + key bytes
		if PEMErr != nil {
			loghub.Err(PEMErr)
		}
	}
	rCAKeyPrivate, rCAKeyPrivateErr := x509.ParsePKCS1PrivateKey(blockBytes) //parse bytes to key
	if rCAKeyPrivateErr != nil {
		loghub.Out(2, "[~] Cannot parse intermediate eternity key!", false)
		loghub.Err(rCAKeyPrivateErr)
	}
	loghub.Out(0, "[~] Intermediate eternity key successfully parsed!", false)

	/*
		PUBLIC KEY CREATION
	*/
	rCAKeyPublic := &rCAKeyPrivate.PublicKey

	/*
		PUBLIC CERTIFICATE CREATION
	*/
	rCACert, rCACertErr := x509.CreateCertificate(rand.Reader, parseInt, parseCA, rCAKeyPublic, caX509.PrivateKey)
	if rCACertErr != nil {
		loghub.Out(2, "[~] Intermediate CA renewal failed", true)
	}

	/*
		PUBLIC CERTIFICATE WRITE TO FILE
	*/
	rCAPublicCert, rCAPublicCertErr := os.Create(sigCA + renewedIntCert)
	if rCAPublicCertErr != nil {
		loghub.Out(2, "[~] Renewal of public part of intermediate CA could not be done for: "+sigCA+renewedRootCert, true)
	}

	/*
		PEM ENCODING -> CERTIFICATE
	*/
	pem.Encode(rCAPublicCert, &pem.Block{Type: "CERTIFICATE", Bytes: rCACert}) //add PEM certificate block encoding
	rCAPublicCert.Close()

	loghub.Out(0, "[~] Renewed public certificate of intermediate CA created in: "+sigCA+renewedRootCert, false)

	/*
		PRIVATE KEY WRITE TO FILE
	*/
	rCAPrivateCert, rCAPrivateCertErr := os.OpenFile(sigCA+renewedIntKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) //this is not just os.Create since we need 0600 for the key
	if rCAPrivateCertErr != nil {
		loghub.Out(2, "[~] Intermediate eternity key could not be copied to: "+sigCA+renewedIntKey, true)
	}

	/*
		PEM ENCODING -> PRIVATE KEY
	*/
	pem.Encode(rCAPrivateCert, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rCAKeyPrivate)}) //add PEM key block encoding
	rCAPrivateCert.Close()

	loghub.Out(0, "[~] Intermediate eternity key copied to: "+sigCA+renewedIntKey, false)

	/*
		CERTIFICATE VALIDATION
	*/
	loghub.Out(0, "[~] Checking renewed intermediate certificate keypair ...", false)
	_, checkX509Err := tls.LoadX509KeyPair(sigCA+renewedIntCert, sigCA+renewedIntKey) //checking private and public part of the certificate combined
	if checkX509Err != nil {
		panic(checkX509Err)
	} else {
		loghub.Out(0, "[~] Renewed intermediate certificate valid! (RSA)", false)
	}
	//filehandling.CertCombiner(sigCA, renewedIntCert, renewedIntKey, "renewed-intermediate")
	filehandling.SingleFileAppend(sigCA, sigCA+renewedIntCert, sigCA+renewedIntKey, "combined-renewed-intermediate", ".pem")
	return true //there are already a lot of checks beforehand, if we manage to get to this point, everything is ok
}

/*
TEMPORARY DEFAULT
*/
func overwriteCertificates() {
	srcDir := configstruct.CurrentConfig.WebhookServer.Security.TempCertDir      //temporary cert dir contains all necessary combinations of certs
	targetDirRoot := configstruct.CurrentConfig.WebhookServer.Security.RootCADir //root ca directory
	targetDirInt := configstruct.CurrentConfig.WebhookServer.Security.IntCADir   //intermediate ca directory

	//renewedRootCert = "/webhook-server-root-ca.crt"
	os.Remove(targetDirRoot + renewedRootCert)
	filehandling.CopyAtoB(srcDir+renewedRootCert, targetDirRoot+renewedRootCert)

	//renewedRootKey = "/webhook-server-root-ca.key"
	os.Remove(targetDirRoot + renewedRootKey)
	filehandling.CopyAtoB(srcDir+renewedRootKey, targetDirRoot+renewedRootKey)

	//renewedIntCert = "/webhook-server-int-ca.crt"
	os.Remove(targetDirInt + renewedIntCert)
	filehandling.CopyAtoB(srcDir+renewedIntCert, targetDirInt+renewedIntCert)

	//renewedIntKey = "/webhook-server-int-ca.key"
	os.Remove(targetDirInt + renewedIntKey)
	filehandling.CopyAtoB(srcDir+renewedIntKey, targetDirInt+renewedIntKey)

	os.Remove(srcDir + renewedRootCert)              //delete old after copy
	os.Remove(srcDir + renewedRootKey)               //delete old after copy
	os.Remove(srcDir + renewedIntCert)               //delete old after copy
	os.Remove(srcDir + renewedIntKey)                //delete old after copy
	os.Remove(srcDir + "/combined-root.pem")         //if renewed not longer necessary
	os.Remove(srcDir + "/combined-intermediate.pem") //if renewed not longer necessary

	loghub.Out(0, "[~] Cleaned up and overwritten previous certificates!", false)
}

/*
	FEATURE --> not implementing yet
*/
//complete certificate rotation contains backup, cleanup, relocation
func rotateCertificates() bool {
	if backupOldCerts() {
		if cleanupOldCerts() {
			if relocateCertificates() {
				return true
			}
		}
	}
	return false
}

// copy old certificates (root, int, server) to an archive with timestamp, S3 possibility, maybe enable/disable functionality?
func backupOldCerts() bool {
	loghub.Out(0, "[~] Old certificates archived!", false)
	return true
}

// delete old certificates (root, int, server)
func cleanupOldCerts() bool {
	loghub.Out(0, "[~] Old certificates removed from main directories!", false)
	return true
}

// move renewed certificates (root) to main directory to trigger default creation (int, server) process
func relocateCertificates() bool {
	loghub.Out(0, "[~] New certificates placed correctly!", false)
	return true
}
