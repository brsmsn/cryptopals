package main

import "testing"

func TestHexToBase64(t *testing.T) {
	expected := "746865206b696420646f6e277420706c6179"

	val, _ := FixedXOR(Given1, Given2)

	if val != expected {
		t.Errorf("Expected %q, got %q", expected, val)
	}

}
