package main

import (
	"crypto/sha256"
	"math/big"
)

var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func base58Encode(input []byte) string {
	intInput := new(big.Int).SetBytes(input)
	zero := big.NewInt(0)
	fiftyEight := big.NewInt(58)
	if intInput.Cmp(zero) == 0 {
		return string(base58Alphabet[0])
	}
	var encoded []byte
	for intInput.Cmp(zero) > 0 {
		mod := new(big.Int)
		intInput.DivMod(intInput, fiftyEight, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b == 0x00 {
			encoded = append(encoded, base58Alphabet[0])
		} else {
			break
		}
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return string(encoded)
}

func base58CheckEncode(data []byte) string {
	checksum := checksum4(data)
	payload := append(data, checksum...)
	return base58Encode(payload)
}

func checksum4(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:4]
}
