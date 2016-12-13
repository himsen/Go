package main

import (
	"fmt"
	"flag"
	"errors"
	"os"
	"io/ioutil"
	"encoding/hex"
)

/* 
 * Improvements:
 * Use Cloudflare improved GO AES-GCM cipher implementation
 * 
 */

var fkey string 
var fenc string
var fdec string

func init() {

	flag.StringVar(&fkey, "k", "", "Path to key")
	flag.StringVar(&fenc, "e", "", "Path to plaintext file")
	flag.StringVar(&fdec, "d", "", "Path to ciphertext file")

}

func main() {

	flag.Parse()

	var key []byte

	//Read key
	if _, err := readkey(); err != nil {
		fmt.Fprintf(os.Stderr, "Reading key failed: %v\n", err)
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

	fmt.Println("Flag contens:")
	fmt.Println("key:", fkey)
	fmt.Println("Plaintext:", fenc)
	fmt.Println("Ciphertext:", fdec)



}

func checkerror(err error) {

	if err != nil {
		panic(err)
	}

}

func doespathexist(path string) (bool, string) {

    if _, err := os.Stat(path); err != nil {
    	if os.IsNotExist(err) {
        	return false, "Provided key file does not exists" //No
    	} else {
        	return false, "Might be a permission error with provided key file" //Or no
    	}
	}

	return true, "" //Yes

}

func readkey() ([]byte, error) {

	var binkey []byte

	//Check if key file is provided 
	if len(fkey) == 0 {
		//Can't encrypt/decrypt without a key
		return nil, errors.New("No key file provided")
	}

	//Check if key file exists
	if pathexists, errstr := doespathexist(fkey); !pathexists {
		return nil, errors.New(errstr)
	}

	//Read key file
	hexkey, err := ioutil.ReadFile(fkey)
	checkerror(err)

	//Check if the file contains data
	if len(hexkey) - 1 == 0 {
		return nil, errors.New("No key in key file")
	}

	//Remove newline
	hexkey = hexkey[:len(hexkey) - 1]

	fmt.Println(hexkey)
	//Key is assumed to be hex encoded
	//Convert hex encodd key to binary
	binkey = make([]byte, hex.DecodedLen(len(hexkey)))
	nbytes, err := hex.Decode(binkey, hexkey)
	checkerror(err)

	//Check if key have correct length (256 bits)
	if nbytes * 8 != 256 {
		return nil, errors.New("Key has illigal length")
	} 

	//Return parsed binary key
	return binkey, nil
}

//Implement using Cloudflare crypto library

func enc(key []byte) (error) {

	//Check if encrypt flag is set
	if len(fenc) == 0 {
		//Do nothing
		return nil
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


