package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// 输入格式示例：101001011010... 或 1 0 1 0 0 1 ...
func main() {
	fmt.Println("请输入掷硬币结果（0=反面, 1=正面），可用空格或连续输入：")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.ReplaceAll(line, " ", "")
	line = strings.TrimSpace(line)

	// 检查输入长度
	if len(line) < 128 {
		log.Fatalf("位数不足（当前 %d bits），生成12词至少128位，生成24词至少256位", len(line))
	}

	// 决定助记词长度
	bitCount := len(line)
	var entropyBytes []byte
	if bitCount >= 256 {
		entropyBytes = bitsToBytes(line[:256])
	} else {
		entropyBytes = bitsToBytes(line[:128])
	}

	// 生成助记词
	mnemonic, err := bip39.NewMnemonic(entropyBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n✅ 生成的助记词如下：")
	fmt.Println(mnemonic)
}

// 将 "010101..." 字符串转为字节数组
func bitsToBytes(bits string) []byte {
	n := new(big.Int)
	n.SetString(bits, 2)
	bytes := n.Bytes()

	// 补足长度 (16字节或32字节)
	if len(bytes) < 16 {
		padding := make([]byte, 16-len(bytes))
		bytes = append(padding, bytes...)
	} else if len(bytes) < 32 && len(bits) >= 256 {
		padding := make([]byte, 32-len(bytes))
		bytes = append(padding, bytes...)
	}

	fmt.Printf("熵(hex)：%s\n", hex.EncodeToString(bytes))
	return bytes
}
