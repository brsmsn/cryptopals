/*
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
*/

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
)

//Given1 first given
var Given1 = "1c0111001f010100061a024b53535009181c"

//Given2 second given
var Given2 = "686974207468652062756c6c277320657965"

func main() {
	xor, err := FixedXOR(Given1, Given2)

	if err == nil {
		fmt.Println(xor)
	} else {
		fmt.Println("Can not xor number")
	}
}

//FixedXOR returns the XOR combination of two numbers of equal length
func FixedXOR(num1, num2 string) (string, error) {
	if len(num1) != len(num2) {
		return "", errors.New("Numbers are not equal in length")
	}

	buf1, err := hex.DecodeString(num1)
	buf2, err := hex.DecodeString(num2)

	if err == nil {
		var xor []byte
		xor = make([]byte, len(buf1), len(buf1))
		for i := range buf1 {
			xor[i] = buf1[i] ^ buf2[i]
		}

		return hex.EncodeToString(xor), nil
	}

	return "", err
}
