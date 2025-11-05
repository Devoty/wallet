package main

import (
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	// 原始秘密
	secret := []byte("This is a super secret message!")

	// 拆分为 5 份，门限为 3
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		panic(err)
	}

	fmt.Println("Generated Shares:")
	for i, share := range shares {
		fmt.Printf("Share %d: %x\n", i+1, share)
		mnemonic, err := bip39.NewMnemonic(share)
		if err != nil {
			return
		}
		fmt.Printf("\nmnemonic mnemonic: %s\n", mnemonic)
	}

	// 模拟用前3份恢复
	recovered, err := shamir.Combine(shares[:3])
	if err != nil {
		panic(err)
	}

	fmt.Printf("\nRecovered Secret: %s\n", recovered)
}
