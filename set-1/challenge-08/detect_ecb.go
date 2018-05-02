/*Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; th
*/

package main

import (
	"bufio"
	"fmt"
	"os"
)

const blockSize = 16

func main() {

	f, err := os.Open("file.txt")
	checkErr(err)

	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		texts := detectRepBlocks([]byte(line))

		if texts {
			fmt.Println("repeating ciphertext: \n" + line)
		}

	}

}

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
	}
}

func detectRepBlocks(cipherTxt []byte) bool {

	blocks := make(map[string]int)

	for i := 0; i < len(cipherTxt); i += blockSize {
		block := string(cipherTxt[i : i+16])

		//ECB has repeating blocks, a proper mode of operation would have no
		//duplicate blocks
		if _, isInMap := blocks[block]; isInMap {
			return true
		}

		blocks[block] = 1
	}

	return false
}
