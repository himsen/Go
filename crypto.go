package main

import (
	"fmt"
	"flag"
	"errors"
	"os"
	"io/ioutil"
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
)

/* 
 * Improvements:
 * Use Cloudflare's improved GO crypto implementation
 * 
 */

var fkey string 
var fenc string
var fdec string

func init() {

	flag.StringVar(&fkey, "k", "", "Hex encoded key")
	flag.StringVar(&fenc, "e", "", "Path to plaintext file")
	flag.StringVar(&fdec, "d", "", "Path to ciphertext file")

}

func main() {

	flag.Parse()

	//Read key
	key, err := parsekey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parsing key failed: %v\n", err)
		os.Exit(1)
	}

	//Encrypt
	if err := enc(key); err != nil {
		fmt.Fprintf(os.Stderr, "Encryption failed")
		os.Exit(1)
	}

	//Decrypt
	if err := dec(key); err != nil {
		fmt.Fprintf(os.Stderr, "Decryption failed")
		os.Exit(1)
	}

	fmt.Println("Flag contents:")
	fmt.Println("key:", fkey)
	fmt.Println("Plaintext:", fenc)
	fmt.Println("Ciphertext:", fdec)



}

func checkerror(err error) {

	if err != nil {
		panic(err)
	}

}

func doesfileexist(path string) (bool, string) {

    if _, err := os.Stat(path); err != nil {
    	if os.IsNotExist(err) {
        	return false, "Provided file does not exists" //No
    	} else {
        	return false, "Might be a permission error with provided file" //Or no
    	}
	}

	return true, "" //Yes

}

func readfile(path string) ([]byte, error) {

	var data []byte

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

func parsekey() ([]byte, error) {

	//Key length (counted in bytes)
	keylen := hex.DecodedLen(len(fkey))

	//Check if key has correct (paranoid level) length (256 bits)
	if keylen * 8 != 256 {
		return nil, errors.New("Key has illegal length")
	} 

	//Convert hex encoded key (string) to binary
	binkey := make([]byte, keylen)
	binkey, err := hex.DecodeString(fkey)
	checkerror(err)

	//Return parsed binary key
	return binkey, nil

}

func enc(key []byte) (error) {

	//Check if encrypt flag is set
	if len(fenc) == 0 {
		//Do nothing
		return nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return errors.New("Encryption failed")
	}

	return nil

}

func dec(key []byte) (error) {

	//Check if decrypt flag is set
	if len(fdec) == 0 {
		//Do nothing
		return nil
	}

	return nil

}


