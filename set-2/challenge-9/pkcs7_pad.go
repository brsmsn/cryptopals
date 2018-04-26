/*Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
plaintext into ciphertext. But we almost never want to transform a single block;
we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a
plaintext that is an even multiple of the blocksize. The most popular padding
scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes
of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
*/

package main

import (
	"errors"
	"fmt"
)

func main() {
	txt := []byte("YELLOW SUBMARINE")
	txt, _ = pkcs7Pad(txt, 20)
	fmt.Println(txt)
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
