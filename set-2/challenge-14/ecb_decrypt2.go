/*
Byte-at-a-time ECB decryption (Harder)
Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
*/

package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/brsmsn/cryptopals/set-1/challenge-07/ecb"
)

const payload = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkKaksjdhaksdjh`

func main() {
	key := genKey()
	blocksize := findBlocksize(key)
	mode := detectMode([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	plaintxt := make([]byte, 0)
	unknown, _ := base64.StdEncoding.DecodeString(payload)

	if mode == "ecb" {
		for k := 0; k <= len(pad(unknown)); k += blocksize {
			for i := 1; i <= blocksize; i++ {
				//build controlled input, each iteration is 1 byte short
				inputblock := make([]byte, blocksize-i)
				for k := range inputblock {
					inputblock[k] = byte('A')
				}

				//build dictionary based on previous findings and the constructed inputblock
				//each iteration is 1 byte longer as we have found
				//the last byte of the previous iteration.
				dict := buildDict(append(inputblock, plaintxt...), unknown, key)
				ct := oracle(append(inputblock, unknown...), key)

				for j := 0; j <= 255; j++ {
					str := []byte(dict[byte(j)])

					//prevent from going out of bounds
					if blocksize+k > len(pad(unknown)) {
						break
					}

					if reflect.DeepEqual(str[k:blocksize+k], ct[k:blocksize+k]) {
						plaintxt = append(plaintxt, byte(j))
						break
					}
				}
			}
		}
	}

	fmt.Println(string(plaintxt))
}

func buildDict(input, payload, key []byte) map[byte]string {
	dict := make(map[byte]string)

	for i := 0; i <= 255; i++ {
		in := append(input, byte(i))
		dict[byte(i)] = string(oracle(append(in, payload...), key))
	}

	return dict
}

func genKey() []byte {
	key := make([]byte, 16)
	rand.Read(key)
	return key
}

func oracle(pt, key []byte) []byte {
	newPt := pad(pt)
	ct := make([]byte, len(newPt))

	block, _ := aes.NewCipher(key)
	mode := ecb.NewECBEncrypter(block)
	mode.CryptBlocks(ct, newPt)
	return ct
}

//pad text to a multiple of 16 bytes
func pad(text []byte) []byte {
	blocksToPad := 16 - len(text)%16

	if blocksToPad == 0 || blocksToPad == 16 {
		return text
	}

	padded := text
	for i := 0; i < blocksToPad; i++ {
		padded = append(padded, byte(blocksToPad))
	}

	return padded
}

func findBlocksize(key []byte) int {
	var blocksize int
	var curr int

	for i := 0; i < 500; i++ {
		pt := []byte("A")
		ct := oracle(pt, key)
		prevsize := len(ct)

		pt = append(pt, []byte("A")...)

		ct2 := oracle(pt, key)
		nextsize := len(ct2)

		curr = nextsize - prevsize
		if curr > 0 && blocksize < curr {
			blocksize = curr
		} else if curr == 0 {
			blocksize = nextsize
		}
	}
	return blocksize
}

func detectMode(ct []byte) string {
	blocks := make(map[string]int)

	for i := 0; i < len(ct); i += 16 {
		block := string(ct[i : i+16])

		if _, isInMap := blocks[block]; isInMap {
			return "ecb"
		}

		blocks[block] = 1
	}

	return "cbc"
}
