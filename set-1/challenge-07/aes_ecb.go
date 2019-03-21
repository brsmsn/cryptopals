/*
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB
mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're
having you get ECB working in code for a reason. You'll need it a lot later on,
and not just for attacking ECB.
*/

package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/brsmsn/cryptopals/set-1/challenge-07/ecb"
)

func main() {
	//16 byte key = aes 128
	key := []byte("YELLOW SUBMARINE")

	file, err := ioutil.ReadFile("file.txt")
	checkErr(err)

	cipherTxt, _ := base64.StdEncoding.DecodeString(string(file))

	fmt.Println(decryptAESECBGEN(key, cipherTxt))
}

//uses ecb.go, implementation of cipher.go for ecb
func decryptAESECBGEN(key []byte, cipherTxt []byte) string {
	block, err := aes.NewCipher(key)
	checkErr(err)

	mode := ecb.NewEBCDecrypter(block)
	mode.CryptBlocks(cipherTxt, cipherTxt)

	return string(cipherTxt)
}

func decryptAESECB(key []byte, cipherTxt []byte) string {
	block, err := aes.NewCipher(key)
	checkErr(err)

	plaintxt := make([]byte, len(cipherTxt))

	for i := 0; i < len(cipherTxt); i += 16 {
		block.Decrypt(plaintxt[i:i+16], cipherTxt[i:i+16])
	}

	return string(plaintxt)
}

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}
