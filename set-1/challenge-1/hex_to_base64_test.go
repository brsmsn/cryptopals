package main

import "testing"

func TestHexToBase64(t *testing.T) {
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	val, _ := ToBase64(Hex)

	if val != expected {
		t.Errorf("Expected %q, got %q", expected, val)
	}

}
