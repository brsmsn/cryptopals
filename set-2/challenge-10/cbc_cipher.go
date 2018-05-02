/*Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
messages, despite the fact that a block cipher natively only transforms
individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before
the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is
added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making
it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to
test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW
SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
What's the point of even doing this stuff if you aren't going to learn from it?
*/

package main

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
)

func main() {
	//16 byte key = aes 128
	key := []byte("YELLOW SUBMARINE")
	//iv needs to be the same length as an aes block size
	iv := make([]byte, 16)

	file, _ := ioutil.ReadFile("file.txt")

	txt, _ := base64.StdEncoding.DecodeString(string(file))

	fmt.Println(decryptAESCBC(key, txt, iv))
}

func decryptAESCBC(key []byte, cipherTxt, iv []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Cipher initializing failed")
	}

	var plaintxt []byte
	prev := iv

	for i := 0; i < len(cipherTxt); i += 16 {
		temp := make([]byte, 16)
		ci := cipherTxt[i : i+16]
		if len(cipherTxt[i:i+16]) != 16 {
			ci, _ = pkcs7Pad(cipherTxt[i:i+16], 16)
		}

		block.Decrypt(temp, ci)
		plaintxt = append(plaintxt, xor(temp, prev)...)
		prev = ci
	}

	return string(plaintxt)
}

func encryptAESCBC(key []byte, ptxt, iv []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("Cipher initializing failed")
	}

	ctxt := make([]byte, len(ptxt))
	prev := iv

	for i := 0; i < len(ptxt); i += 16 {
		ci := ptxt[i : i+16]
		if len(ptxt[i:i+16]) != 16 {
			ci, _ = pkcs7Pad(ptxt[i:i+16], 16)
		}
		block.Encrypt(ctxt[i:i+16], xor(ci, prev))
		prev = ctxt[i : i+16]
	}

	return string(ctxt)
}

func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func pkcs7Pad(text []byte, blockToPad int) ([]byte, error) {
	if len(text) > blockToPad {
		return nil, errors.New("The text to pad is already larger than the specified number")
	}

	if blockToPad < 0 {
		return nil, errors.New("Specified number to pad can not be negative")
	}

	if blockToPad > 256 {
		return nil, errors.New("Out of specs")
	}

	toPad := blockToPad - len(text)

	for i := 0; i < toPad; i++ {
		text = append(text, byte(toPad))
	}

	return text, nil
}
