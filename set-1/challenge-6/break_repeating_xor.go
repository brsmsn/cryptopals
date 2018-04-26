/*
Break repeating-key XOR
It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone
coding. The other challenges in this set are there to bring you up to speed.
This one is there to qualify you. If you can do this one, you're probably just
fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key
XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two
strings. The Hamming distance is just the number of differing bits. The distance
between:


this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.


For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE
worth of bytes, and find the edit distance between them. Normalize this result
by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You
could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE
blocks instead of 2 and average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of
KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block,
and a block that is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do
this.
For each block, the single-byte XOR key that produces the best looking histogram
is the repeating-key XOR key byte for that block. Put them together and you have
the key.
This code is going to turn out to be surprisingly useful later on. Breaking
repeating-key XOR ("Vigenere") statistically is obviously an academic exercise,
a "Crypto 101" thing. But more people "know how" to break it than can actually
break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other
ones. We promise, there aren't any blatant errors in this text. In particular:
the "wokka wokka!!!" edit distance really is 37.
*/

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/bits"
)

//from A to Z
var freq = [...]float64{
	0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
	0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
	0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
	0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
}

var fileName = "file.txt"

func main() {
	file, err := ioutil.ReadFile(fileName)
	checkErr(err)
	cipherTxt, err := base64.StdEncoding.DecodeString(string(file))
	checkErr(err)
	plaintext := DecipherRepXOR(cipherTxt)
	fmt.Println(plaintext)
}

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}

//DecipherRepXOR given a txt encrypted with a repeating XOR cipher, find the plaintext.
func DecipherRepXOR(cipherText []byte) string {
	keysize := guessKeySize(cipherText, 40)
	key := findKey(cipherText, keysize)

	plaintext := make([]byte, len(cipherText))

	for i := range plaintext {
		plaintext[i] = cipherText[i] ^ key[i%len(key)]
	}

	return string(plaintext)
}

//guessKeys finds the best possible key length.
func guessKeySize(ciphertext []byte, maxIt int) int {
	keysize := 2
	bestscore := math.MaxFloat64
	bestsize := -1

	for ; keysize <= maxIt; keysize++ {
		//first and second keywords worth of bytes are in a block that is a multiple of keysize
		//this is to get a more accurate distance i.e reduce noise and therefore have
		//more accurate results
		firstb := ciphertext[:keysize*4]
		secondb := ciphertext[keysize*4 : keysize*2*4]
		dst, err := hammingDst(firstb, secondb)
		checkErr(err)
		totdst := float64(dst) / float64(keysize)

		if totdst < bestscore {
			bestscore = totdst
			bestsize = keysize
		}
	}
	return bestsize
}

//hammingDst calculates the hamming distance between two strings.
func hammingDst(txt, txt2 []byte) (int, error) {
	score := 0

	if len(txt) != len(txt2) {
		return -1, errors.New("Parameters are not of the same length")
	}

	for i, x := range txt {
		//we xor the 2 values since we only care about the bits that are different
		bitVal := x ^ txt2[i]
		score += bits.OnesCount8(bitVal)
	}

	return score, nil
}

func findKey(ctxt []byte, size int) string {
	blocks := make([][]byte, len(ctxt)/size)
	key := ""

	//break ciphertext into blocks of keysize
	for i := 0; i < len(ctxt)/size; i++ {
		blocks[i] = ctxt[i*size : (i*size)+size]
	}

	//Turn each column into a row (transposition of a matrix). Remember we broke our ciphertext into keysize blocks
	//that means each column in our matrix has been encrypted with the same byte.
	for i := 0; i < size; i++ {
		col := make([]byte, len(blocks))

		for k := 0; k < len(blocks); k++ {
			col[k] = blocks[k][i]
		}
		//We can use our solution to challenge-3/4 to find the key used to encrypt col.
		_, subKey, _ := Decipher(col)
		//build the key from each successfull col decipher
		key += subKey
	}

	return key
}

//Decipher deciphers a given ciphertext
func Decipher(ctxt []byte) (string, string, float64) {
	plaintext := make([]byte, len(ctxt))
	txt := ""
	high := 0.0
	key := ""

	//we loop around all possible ASCII characters as one of these character
	// was used as the key.
	for i := 0; i < 256; i++ {

		for k := 0; k < len(ctxt); k++ {
			plaintext[k] = byte(ctxt[k] ^ byte(i))
		}

		score := getScore(plaintext)

		//a low score means that the deciphered plaintext is the closest to our expected(english text)
		if score > high {
			txt = string(plaintext)
			high = score
			key = string(byte(i))
		}
	}

	return txt, key, high
}

//get score
func getScore(ctxt []byte) float64 {

	var alpCount [26]int
	validCharCount := 0

	//get observed number of occurence for each char in ctxt
	for _, val := range ctxt {
		if val >= 0x41 && val <= 0x5A /*for A to Z*/ {
			val = val + (0x5A - 0x41)
		}
		if val >= 0x61 && val <= 0x7A /*for a to z*/ {
			alpCount[int(val-0x61)]++
			validCharCount++
		}
	}

	chi := 0.0
	//chi square here will fail
	for i, val := range alpCount {
		//The score for a letter is: the expected occurence (freq of letter * length of text) of that
		//letter multiplied by the observed occurence of that letter within the text.
		//We can assume that letters with the highest frequency will make the bulk of the sentence,
		//so if these letter are not present the score will be effectively penalized.
		chi += freq[i] * float64(validCharCount) * float64(val)
	}
	return chi
}
