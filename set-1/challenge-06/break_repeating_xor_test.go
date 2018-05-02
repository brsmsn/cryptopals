package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestHaming(t *testing.T) {
	var expected = 37
	var param1 = "this is a test"
	var param2 = "wokka wokka!!!"

	val, err := hammingDst([]byte(param2), []byte(param1))
	fmt.Println(val)
	if err != nil {
		t.Errorf("Error")
	} else if val != expected {
		t.Errorf("Value does not match expected")
	}
}

func TestGuessKeys(t *testing.T) {
	file, _ := ioutil.ReadFile("file.txt")
	cipherTxt, _ := base64.StdEncoding.DecodeString(string(file))
	distances := guessKeySize(cipherTxt, 40)
	fmt.Println(distances)

}

func TestFindKey(t *testing.T) {
	file, _ := ioutil.ReadFile("file.txt")
	cipherTxt, _ := base64.StdEncoding.DecodeString(string(file))
	distances := guessKeySize(cipherTxt, 40)
	key := findKey(cipherTxt, distances)
	fmt.Println(key)
}
