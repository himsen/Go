package main

import (
	"fmt"
	"flag"
	"errors"
	"os"
	"io/ioutil"
	"io"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

/* 
 * Improvements:
 * Use Cloudflare's improved GO crypto implementation
 * Better handling of large files
 * Unify error messages
 * Support for alternative input methods
 * Support for alternative encodings
 * Support for alternative ciphers (e.g. stream cipher)
 * Support for setting permissions of output file
 * Support for less paranoid key lengths
 */

var fkey string 
var fenc string
var fdec string
var fdumphexciphertext bool

func init() {

	flag.StringVar(&fkey, "k", "", "Hex encoded key")
	flag.StringVar(&fenc, "e", "", "Path to plaintext file")
	flag.StringVar(&fdec, "d", "", "Path to ciphertext file")
	flag.BoolVar(&fdumphexciphertext, "ctdump", false, "Dump hex encoded ciphertext after encryption")

}

func main() {

	flag.Parse()

	//Parse key
	key, err := parsekey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parsing key failed: %v\n", err)
		os.Exit(1)
	}

	//Encrypt
	if err := enc(key); err != nil {
		fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
		os.Exit(1)
	}

	//Decrypt
	if err := dec(key); err != nil {
		fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
		os.Exit(1)
	}

}

//Panic errors!!!
func checkerror(err error) {

	if err != nil {
		panic(err)
	}

}

//Checks whether a file exists. If not, checks what the problem might be. 
func doesfileexist(path string) (bool, string) {

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, "Provided file does not exist" //No
		} else {
			return false, "There might be a permission error with provided file" //Problems
		}
	}

	return true, "" //Yes

}

//Reads a file and basic sanity checks.
func readfile(path string) ([]byte, error) {

	//Check if file exists
	if fileexists, errstr := doesfileexist(path); !fileexists {
		return nil, errors.New(errstr)
	}

	//Read file
	//For simplicity assume we are dealing with small files
	data, err := ioutil.ReadFile(path)
	checkerror(err)

	//Check if the file contains data
	if len(data) == 0 {
		return nil, errors.New("No data in file")
	}

	return data, nil

}

//Generate a random Nonce.
//Responsibility of the user to not invoke this function
//too many times using the same key.
func GenerateNonce(noncesize int) ([]byte) {

	nonce := make([]byte, noncesize)

	//Use crypto RNG
	_, err := io.ReadFull(rand.Reader, nonce)
	checkerror(err)

	return nonce
}

//Parse the user-defined key.
//Key is assumed to be hex encoded.
func parsekey() ([]byte, error) {

	//Key length (counted in bytes)
	keylen := hex.DecodedLen(len(fkey))

	//Check if key has correct (paranoid level) length (32 bytes)
	if keylen != 32 {
		fmt.Println("Wrong key length:", keylen)
		return nil, errors.New("Key has illegal length")
	} 

	//Convert hex encoded key (string) to binary
	binkey := make([]byte, keylen)
	binkey, err := hex.DecodeString(fkey)
	checkerror(err)

	return binkey, nil

}

//Encrypts the content of a the file 'fenc' and writes the
//resulting ciphertext to the file './ciphertext'.
//Provides both confidentiality and authentication.
func enc(key []byte) (error) {

	//Check if encrypt flag is set
	if len(fenc) == 0 {
		//Do nothing
		return nil
	}

	//Read plaintext file (if it exists)
	plaintext, err := readfile(fenc)
	if err != nil {
		return err
	}

	//Initialise AES cipher
	aescipher, err := aes.NewCipher(key)
	if err != nil {
		return errors.New("Cipher initialisation")
	}

	//Initialise GCM mode
	aesgcm, err := cipher.NewGCM(aescipher)
	if err != nil {
		return errors.New("GCM initialisation")
	}

	//Generate nonce (use GCM standard nonce size)
	nonce := GenerateNonce(aesgcm.NonceSize())

	//Encrypt and append result to nonce
	//Hence ciphertext will consist of <nonce + encrypted data + tag>
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	//Write to file
	err = ioutil.WriteFile("ciphertext", ciphertext, 0644)
	checkerror(err)

	//Dump human-readable (hex encoded) ciphertext if specified
	//base64 encoding if we cared about size
	if fdumphexciphertext {
		hexciphertext := make([]byte, hex.EncodedLen(len(ciphertext)))
		hex.Encode(hexciphertext, ciphertext)
		err = ioutil.WriteFile("ciphertextdump", hexciphertext, 0644)
		checkerror(err)
	}

	return nil

}

//Decrypts the content of the file 'fdec' and writes the
//resulting plaintext to the file './plaintext'. 
//Provides both confidentiality and authentication.
func dec(key []byte) (error) {

	//Check if decrypt flag is set
	if len(fdec) == 0 {
		//Do nothing
		return nil
	}

	//Read ciphertext file (if it exists)
	ciphertext, err := readfile(fdec)
	if err != nil {
		return err
	}

	//Initialise AES cipher
	aescipher, err := aes.NewCipher(key)
	if err != nil {
		return errors.New("Cipher initialisation")
	}

	//Initialise GCM mode
	aesgcm, err := cipher.NewGCM(aescipher)
	if err != nil {
		return errors.New("GCM initialisation")
	}

	//Extract nonce
	nonce := make([]byte, aesgcm.NonceSize())
	copy(nonce, ciphertext)

	//Decrypt
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[aesgcm.NonceSize():], nil)
	checkerror(err)

	//Write to file
	err = ioutil.WriteFile("plaintext", plaintext, 0644)
	checkerror(err)

	return nil

}
