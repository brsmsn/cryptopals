/*The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the
message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character
frequency is a good metric. Evaluate each output and choose the one with the
best score.

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
*/

package main

import (
	"encoding/hex"
	"fmt"
	"math"
)

var cipherTxt = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

//English frequency from A to Z
var freq = [...]float64{
	0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
	0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
	0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
	0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
}

func main() {
	texts, key := Decipher(cipherTxt)
	fmt.Println("Key => " + key + "\nCiphertext => " + texts)
}

//Decipher deciphers a given ciphertext
func Decipher(cText string) (string, string) {
	ctxt, _ := hex.DecodeString(cText)
	plaintext := make([]byte, len(ctxt))
	txt := ""
	low := math.MaxFloat64
	key := ""

	//we loop around all possible ASCII characters as one of these character
	//was used as the key.
	for i := 0; i < 256; i++ {

		for k := 0; k < len(ctxt); k++ {
			plaintext[k] = byte(ctxt[k] ^ byte(i))
		}

		score := getScore(plaintext)

		//a low score means that the deciphered plaintext is the closest to our expected(english text)
		if score < low {
			txt = string(plaintext)
			low = score
			key = string(byte(i))
		}
	}

	return txt, key
}

//get score based on chi squared testing.
func getScore(ctxt []byte) float64 {

	var alpCount [26]int
	validCharCount := 0

	//get observed number of occurence for each char in ctxt
	for _, val := range ctxt {
		if val >= 0x41 && val <= 0x5A /*for A to Z*/ {
			alpCount[int(val-0x41)]++
			validCharCount++
		} else if val >= 0x61 && val <= 0x7A /*for a to z*/ {
			alpCount[int(val-0x61)]++
			validCharCount++
		}
	}

	chi2 := 0.0

	//Chi squared
	for i, val := range alpCount {
		//the expected value is the frequency of a letter times the number of valid
		//characters (letters) in the cipher text.
		expected := freq[i] * float64(validCharCount)
		diff := float64(val) - expected
		chi2 += (diff * diff) / expected
	}
	return chi2
}
