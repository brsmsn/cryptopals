package main

import "errors"

func main() {
}

func pkcs7Pad(text []byte, blockToPad int) ([]byte, error) {
	if len(text) < blockToPad {
		return nil, errors.New("The text to pad is already larger than the specified number")
	}

	if blockToPad < 0 {
		return nil, errors.New("Specified number to pad can not be negative")
	}

}
