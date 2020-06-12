/*
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
*/

package main

import (
	"crypto/aes"
	"cryptopals/set-1/challenge-07/ecb"
	"fmt"
	"math/rand"
	"strings"
)

func main() {
	key := genKey()

	in := forgeToAdmin(key)
	pt := string(dec(in, key))
	fmt.Println(pt)
}

func forgeToAdmin(key []byte) []byte {
	//We want to seperate the output into alligned blocks
	n1 := pad([]byte("email=te@te.com"))
	in1 := string(n1[6:]) // removing the "email="

	//needed to ensure we remain block alligned such that we have sufficient blocks to cut
	n2 := pad([]byte("&uid=10&role="))
	in2 := string(n2[13:])

	//very important this is what we will paste to the end
	in3 := string(pad([]byte("admin")))

	in := enc([]byte(profileFor(in1+in3+in2)), key)

	//equals to email=te@te.com
	a := in[0:16]

	//equals to admin0x110x110x110x110x110x110x110x110x110x110x11 (padded with 11)
	b := make([]byte, 16)
	copy(b, in[16:32])

	//equals to &uid=10&role=
	c := in[32:48]

	//D is not needed but contains the literal "user" with its respective pad

	// Making A + B + C + D -> A + C + B
	i := append(a, c...)
	return append(i, b...)
}

func profileFor(payload string) string {
	presafe := strings.ReplaceAll(payload, "&", "")
	presafe2 := strings.ReplaceAll(presafe, "=", "")

	return "email=" + presafe2 + "&" + "uid=10" + "&" + "role=user"
}

func pad(text []byte) []byte {
	blocksToPad := 16 - len(text)%16

	if blocksToPad == 0 || blocksToPad == 16 {
		return text
	}

	padded := text
	for i := 0; i < blocksToPad; i++ {
		padded = append(padded, byte(blocksToPad))
	}

	return padded
}

func unpad(text []byte) []byte {
	pad := text[len(text)-1]

	if int(pad) <= 16 {
		indexPad := len(text) - int(pad) - 1
		n := strings.Count(string(text[indexPad:len(text)]), string(pad))

		if n == int(pad) {
			return text[0 : indexPad+1]
		}
	}

	return text
}

func enc(pt, key []byte) []byte {
	newPt := pad(pt)
	ct := make([]byte, len(newPt))

	block, _ := aes.NewCipher(key)
	mode := ecb.NewECBEncrypter(block)
	mode.CryptBlocks(ct, newPt)
	return ct
}

func dec(ct, key []byte) []byte {
	pt := make([]byte, len(ct))
	block, _ := aes.NewCipher(key)
	mode := ecb.NewECBDecrypter(block)
	mode.CryptBlocks(pt, ct)
	return unpad(pt)
}

func genKey() []byte {
	key := make([]byte, 16)
	rand.Read(key)
	return key
}
