package ecb

import "crypto/cipher"

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEcrypter ecb

type ecbEncAble interface {
	NewEBCEncrypter(b cipher.Block) cipher.BlockMode
}

func NewEBCEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEcrypter)(newECB(b))
}

func (x *ecbEcrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbEcrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

type ecbDecAble interface {
	NewEBCDecrypter(b cipher.Block) cipher.BlockMode
}

func NewEBCDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		x.b.Decrypt(dst[:x.blockSize], dst[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
