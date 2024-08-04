package filehandling

import (
	"encoding/base64"
	"io"
	"io/fs"
	"log"
	"os"
	"strings"
	"webhook-server/loghub"
)

// Counts items in a directory and returns the amount
func GetPathItems(dir string) int {
	list, listErr := os.ReadDir(dir)
	if listErr != nil {
		loghub.Err(listErr)
	}
	amount := len(list)

	return amount
}

// GetFileinPath gets all files in a given directory and returns a []fs.DirEntry array of all files within
func GetFileInPath(dir string) []fs.DirEntry {
	list, listErr := os.ReadDir(dir)
	if listErr != nil {
		loghub.Err(listErr)
	}

	return list
}

// Create directory from given path with some exceptions
func CreateDir(path string) {
	if path != "./" { //we do not need local directory creation
		//some directories could be exploited in a data breach scenario, so we prevent creating specific ones
		forbiddenDir := [9]string{"/tmp", "/sys", "/proc", "/bin", "/run", "WinSxS", "Windows", "System32", "System"}
		for _, v := range forbiddenDir {
			if strings.Contains(path, v) {
				loghub.Out(2, "Will not create "+path, false)
				loghub.Out(1, "Paths containing these exact patterns are forbidden:", false)
				for i := 0; i < len(forbiddenDir); i++ {
					loghub.Out(1, forbiddenDir[i], false)
				}
				loghub.Out(2, "Please use another path!", true)
			}
		}
		pathErr := os.MkdirAll(path, 0777) //create all directories and necessary subdirectories
		if pathErr != nil {
			loghub.Err(pathErr)
		}
	}
}

// StatFile is a simple check, if a given file (string path to file) is existent and is a regular readable file
func StatFile(file string) bool {
	fileObj, fileErr := os.Stat(file)
	if fileErr != nil {
		return false
	}
	if fileObj.IsDir() {
		return false
	}
	return true
}

// CopyAtoB is a simple copy function for files (we need it for our self-signed certificate to add it to a pool of valid CAs; and more)
func CopyAtoB(src string, dest string) {
	if StatFile(src) {
		s, sErr := os.Open(src) //open source file
		if sErr != nil {
			loghub.Err(sErr)
		}
		defer s.Close()            //failsafe
		d, dErr := os.Create(dest) //create destination file
		if dErr != nil {
			loghub.Err(dErr)
		}
		defer d.Close()          //failsafe
		_, cErr := io.Copy(d, s) //we do not need the amount of copied bytes, only an error when something happens
		if cErr != nil {
			loghub.Err(cErr)
		}
	}
}

func ReadFileBytes(path string) []byte {
	if StatFile(path) {
		fileBytes, fileBytesErr := os.ReadFile(path)
		if fileBytesErr != nil {
			loghub.Out(2, "Cannot read file "+path, false)
		}
		return fileBytes
	}
	return nil
}

func ByteToB64(b []byte) string {
	b64 := base64.StdEncoding.EncodeToString(b)
	return b64
}

func B64ToByte(s string) []byte {
	b, bErr := base64.StdEncoding.DecodeString(s)
	if bErr != nil {
		loghub.Err(bErr)
	}
	return b
}

// concatenates CERT + KEY to an output file in a given directory (important for TLS connections)
func CertCombiner(dest string, certfile string, keyfile string, descr string) {
	output := descr + "-combined.pem"
	os.Remove(dest + "/" + output) //delete file if existent since we use the os.O_APPEND flag, this is necessary
	o, oErr := os.OpenFile(dest+"/"+output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if oErr != nil {
		loghub.Err(oErr)
	}
	cBytes, cBytesErr := os.ReadFile(dest + "/" + certfile)
	if cBytesErr != nil {
		loghub.Err(cBytesErr)
	}
	kBytes, kBytesErr := os.ReadFile(dest + "/" + keyfile)
	if kBytesErr != nil {
		loghub.Err(kBytesErr)
	}
	_, cErr := o.Write(cBytes)
	if cErr != nil {
		loghub.Err(cErr)
	}
	_, kErr := o.Write(kBytes)
	if kErr != nil {
		loghub.Err(kErr)
	}
	defer o.Close()
}

// appends content of "appendFilePath" to "sourceFilePath" in new targetDir
func SingleFileAppend(targetDir string, sourceFilePath string, appendFilePath string, descr string, postfix string) {
	output := descr + postfix
	os.Remove(targetDir + "/" + output) //delete file if existent since we use the os.O_APPEND flag, this is necessary
	o, oErr := os.OpenFile(targetDir+"/"+output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if oErr != nil {
		loghub.Err(oErr)
	}
	cBytes, cBytesErr := os.ReadFile(sourceFilePath)
	if cBytesErr != nil {
		loghub.Err(cBytesErr)
	}
	kBytes, kBytesErr := os.ReadFile(appendFilePath)
	if kBytesErr != nil {
		loghub.Err(kBytesErr)
	}
	_, cErr := o.Write(cBytes)
	if cErr != nil {
		loghub.Err(cErr)
	}
	_, kErr := o.Write(kBytes)
	if kErr != nil {
		loghub.Err(kErr)
	}
	defer o.Close()
}

// this is kinda bs but somehow we need to find out what the crt and the key file is
func GetCertFiles(path string) (string, string) {
	certList := GetFileInPath(path) //get all files in specified directory
	var cert, key string

	//keep in mind if there are more .crt or .key files in that directory
	//only the last ones get assigned
	for _, f := range certList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), ".crt") { //I know this is hardcoded, please have a better idea
			cert = path + "/" + f.Name()
		}
	}

	for _, f := range certList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), ".key") { //I know this is hardcoded, please have a better idea
			key = path + "/" + f.Name()
		}
	}

	return cert, key //return both full paths to respective files
}

// this is only for kubernetes secret "optional" mounts, since they somehow mount an empty "shadow" to the target directory
func ProbeCertFiles(path string) bool {
	certList := GetFileInPath(path) //get all files in specified directory
	var cert = "null"
	var key = "null"

	//keep in mind if there are more .crt or .key files in that directory
	//only the last ones get assigned
	for _, f := range certList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), ".crt") { //I know this is hardcoded, please have a better idea
			cert = path + "/" + f.Name()
		}
		log.Println("File:", f.Name()) //debug can be removed safely
	}

	for _, f := range certList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), ".key") { //I know this is hardcoded, please have a better idea
			key = path + "/" + f.Name()
		}
	}

	//we do not have any certificate files in the given directory
	if cert == "null" && key == "null" {
		return false
	}

	//we found certificate files
	return true
}

func GetPKIFileNames(path string) (string, string) {
	fileList := GetFileInPath(path) //get all files in specified directory
	var rootKeyFile, intKeyFile string

	//only the last ones get assigned
	for _, f := range fileList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), "_root_") { //I know this is hardcoded, please have a better idea
			rootKeyFile = f.Name()
		}
	}

	for _, f := range fileList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), "_int_") { //I know this is hardcoded, please have a better idea
			intKeyFile = f.Name()
		}
	}

	return rootKeyFile, intKeyFile //return both full paths to respective files
}

// this is important for creation of a CA pool
func GetAllCertFiles(path string) []string {
	certList := GetFileInPath(path) //get all files in specified directory
	var cert []string

	//keep in mind if there are more .crt or .key files in that directory
	//only the last ones get assigned
	for _, f := range certList { //maybe change to force use of first item in list
		if strings.Contains(f.Name(), ".crt") { //I know this is hardcoded, please have a better idea
			cert = append(cert, f.Name())
		}
	}
	return cert //return full paths to all crt files
}
