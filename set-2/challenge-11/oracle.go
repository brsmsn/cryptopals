/*An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function
that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly)
before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC
the other half (just use random IVs each time for CBC). Use rand(2) to decide
which to use.

Detect the block cipher mode the function is using each time. You should end up
with a piece of code that, pointed at a block box that might be encrypting ECB
or CBC, tells you which one is happening. */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/brsmsn/cryptopals/set-1/challenge-07/ecb"
)

func main() {

	for i := 0; i < 10; i++ {
		pt := []byte("asdasdasdasdasddskgjhdsfkgjbsdkjfhgbdsfjkhgbsdfjkghb")
		ct := (encrypt(pt, genKey()))
		fmt.Println("Encrypted with " + detectMode(ct))
	}

}

func genKey() []byte {
	key := make([]byte, 16)
	rand.Read(key)
	return key
}

func encrypt(pt, key []byte) []byte {
	//generate  random amount of bytes from 5 to 10
	genRand := func() []byte {
		bytes := make([]byte, 1)
		rand.Read(bytes)

		//set bytes2 to an integer between 5 and 10 inclusive
		bytes2 := make([]byte, bytes[0]%10+5)
		rand.Read(bytes2)
		return bytes2
	}

	pt1 := append(pt, genRand()...)
	newPt := pad(append(genRand(), pt1...))
	ct := make([]byte, len(newPt))

	bytes := make([]byte, 1)
	rand.Read(bytes)

	block, _ := aes.NewCipher(key)

	switch bytes[0] % 2 {
	case 0:
		mode := ecb.NewEBCDecrypter(block)
		mode.CryptBlocks(ct, newPt)
	case 1:
		//encrrypt with cbc
		iv := make([]byte, 16)
		rand.Read(iv)
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ct, newPt)
	}
	return ct
}

//pad text to a multiple of 16 bytes
func pad(text []byte) []byte {
	blocksToPad := 16 - len(text)%16

	if blocksToPad == 0 {
		return text
	}

	padded := text
	for i := 0; i < blocksToPad; i++ {
		padded = append(padded, byte(blocksToPad))
	}

	return padded
}

func detectMode(ct []byte) string {
	blocks := make(map[string]int)

	for i := 0; i < len(ct); i += 16 {
		block := string(ct[i : i+16])

		//ECB has repeating blocks, a proper mode of operation would have no
		//duplicate blocks
		if _, isInMap := blocks[block]; isInMap {
			return "ecb"
		}

		blocks[block] = 1
	}

	return "cbc"
}
