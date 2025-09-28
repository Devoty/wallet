// dice2bip39_auto.go
// 自动生成 50 个骰子结果，生成 12 个 BIP39 助记词
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
)

// 生成随机骰子（1-6）
func randomDice(n int) ([]int, error) {
	dice := make([]int, n)
	for i := 0; i < n; i++ {
		r, err := rand.Int(rand.Reader, big.NewInt(6))
		if err != nil {
			return nil, err
		}
		dice[i] = int(r.Int64()) + 1 // 1-6
	}
	return dice, nil
}

// 骰子序列转 big.Int（base6）
func diceToBigInt(dice []int) *big.Int {
	result := big.NewInt(0)
	base := big.NewInt(6)
	for _, d := range dice {
		val := big.NewInt(int64(d - 1))
		result.Mul(result, base)
		result.Add(result, val)
	}
	return result
}

func powInt(base, exp int) *big.Int {
	result := big.NewInt(1)
	if exp < 0 {
		return result
	}
	b := big.NewInt(int64(base))
	for i := 0; i < exp; i++ {
		result.Mul(result, b)
	}
	return result
}

func generateEntropyFromDice(numDice, bits int) ([]byte, []int, error) {
	if bits%8 != 0 {
		return nil, nil, errors.New("bits must be a multiple of 8")
	}
	target := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	space := powInt(6, numDice)
	threshold := new(big.Int).Set(space)
	remainder := new(big.Int).Mod(threshold, target)
	threshold.Sub(threshold, remainder)
	for {
		dice, err := randomDice(numDice)
		if err != nil {
			return nil, nil, err
		}
		value := diceToBigInt(dice)
		if value.Cmp(threshold) >= 0 {
			continue
		}
		entropyInt := new(big.Int).Mod(value, target)
		return entropyInt.FillBytes(make([]byte, bits/8)), dice, nil
	}
}

// big.Int 转二进制字符串，补齐长度
func bigIntToBinStr(n *big.Int, length int) string {
	bin := fmt.Sprintf("%b", n)
	if len(bin) < length {
		return strings.Repeat("0", length-len(bin)) + bin
	}
	return bin[:length]
}

func main() {
	entropyBytes, dice, err := generateEntropyFromDice(50, 128)
	if err != nil {
		fmt.Println("生成熵失败:", err)
		return
	}

	// 展示骰子序列
	diceStr := make([]string, len(dice))
	for i, d := range dice {
		diceStr[i] = fmt.Sprintf("%d", d)
	}
	fmt.Println("接受的骰子序列:", strings.Join(diceStr, " "))

	entropyBin := bigIntToBinStr(new(big.Int).SetBytes(entropyBytes), 128)

	// SHA256（展示校验位）
	h := sha256.Sum256(entropyBytes)
	hashBin := bigIntToBinStr(new(big.Int).SetBytes(h[:]), 256)
	checksumBits := 128 / 32
	checksum := hashBin[:checksumBits]
	combined := entropyBin + checksum

	mnemonic, err := bip39.NewMnemonic(entropyBytes)
	if err != nil {
		fmt.Println("生成助记词失败:", err)
		return
	}

	fmt.Println("熵 (bin,128位):", entropyBin)
	fmt.Println("校验和:", checksum)
	fmt.Println("拼接后 (132位):", combined)
	fmt.Println("助记词 (12 个):")
	fmt.Println(mnemonic)

	seed := bip39.NewSeed(mnemonic, "")
	fmt.Println("BIP39 种子 (hex, 无额外口令):", fmt.Sprintf("%x", seed))
	fmt.Println("请在离线安全环境中运行，并考虑设置额外 BIP39 口令。")
}
