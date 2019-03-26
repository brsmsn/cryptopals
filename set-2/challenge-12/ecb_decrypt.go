/*
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode
using a consistent but unknown key (for instance, assign a single random key,
once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by
hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle
function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1
byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the
cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step
anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for
instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the
oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to
the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the
first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your
dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.
Congratulations.
This is the first challenge we've given you whose solution will break real
crypto. Lots of people know that when you encrypt something in ECB mode, you can
see penguins through it. Not so many of them can decrypt the contents of those
ciphertexts, and now you can. If our experience is any guideline, this attack
will get you code execution in security tests about once a year.
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
YnkK`

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
