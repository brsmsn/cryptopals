/*Detect single-character XOR
One of the 60-character strings in this file has been encrypted by
single-character XOR.

Find it.

(Your code from #3 should help.)
*/
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

//English frequency from A to Z
var freq = [...]float64{
	0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
	0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
	0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
	0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
}

var fileName = "file.txt"

func main() {
	f, err := os.Open(fileName)
	check(err)

	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	highest := 0.0
	key := ""
	pt := ""

	for scanner.Scan() {
		texts, key1, score := Decipher(scanner.Text())
		if score > highest {
			highest = score
			key = key1
			pt = texts
		}
	}
	fmt.Println("Key => " + key + "\nScore => " + strconv.FormatFloat(highest, 'f', 6, 64) + "\nCiphertext => " + pt)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

//Decipher deciphers a given ciphertext
func Decipher(cText string) (string, string, float64) {
	ctxt, _ := hex.DecodeString(cText)
	plaintext := make([]byte, len(ctxt))
	txt := ""
	high := 0.0
	key := ""

	//we loop around all possible ASCII characters as one of these character
	//was used as the key.
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

//get score based on custom scoring function
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
	//chi squared here will fail
	for i, val := range alpCount {
		//The score for a letter is: the expected occurence (freq of letter * length of text) of that
		//letter multiplied by the observed occurence of that letter within the text.
		//We can assume that letters with the highest frequency will make the bulk of the sentence,
		//so if these letter are not present the score will be effectively penalized.
		chi += freq[i] * float64(validCharCount) * float64(val)
	}
	return chi
}
