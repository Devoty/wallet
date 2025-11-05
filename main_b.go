// dice2bip39_auto.go
// 自动生成 50 个骰子结果，生成 12 个 BIP39 助记词
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/crypto"
	bip39 "github.com/tyler-smith/go-bip39"
)

// DiceMnemonicResult 汇总骰子助记词生成的关键信息，便于 API 与页面展示。
type DiceMnemonicResult struct {
	Dice              []int    `json:"dice"`
	DiceText          string   `json:"dice_text"`
	EntropyBits       string   `json:"entropy_bits"`
	ChecksumBits      string   `json:"checksum_bits"`
	CombinedBits      string   `json:"combined_bits"`
	Mnemonic          string   `json:"mnemonic"`
	MnemonicWords     []string `json:"mnemonic_words"`
	SeedHex           string   `json:"seed_hex"`
	BTCAddress        string   `json:"btc_address"`
	BTCWIF            string   `json:"btc_wif"`
	ETHAddress        string   `json:"eth_address"`
	ETHPrivateHex     string   `json:"eth_private_hex"`
	USDTAddress       string   `json:"usdt_address"`
	OutputLines       []string `json:"output_lines"`
	NumDice           int      `json:"num_dice"`
	EntropyBitLength  int      `json:"entropy_bit_length"`
	ChecksumBitLength int      `json:"checksum_bit_length"`
}

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

func deriveChild(master *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	key := master
	var err error
	for _, index := range path {
		key, err = key.Child(index)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func btcAddressFromKey(key *hdkeychain.ExtendedKey) (string, string, error) {
	priv, err := key.ECPrivKey()
	if err != nil {
		return "", "", err
	}
	compressedPubKey := priv.PubKey().SerializeCompressed()
	hash160 := btcutil.Hash160(compressedPubKey)
	addr, err := btcutil.NewAddressPubKeyHash(hash160, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", err
	}
	wif, err := btcutil.NewWIF(priv, &chaincfg.MainNetParams, true)
	if err != nil {
		return "", "", err
	}
	return addr.EncodeAddress(), wif.String(), nil
}

func ethAddressFromKey(key *hdkeychain.ExtendedKey) (string, string, error) {
	priv, err := key.ECPrivKey()
	if err != nil {
		return "", "", err
	}
	ecdsaKey := priv.ToECDSA()
	addr := crypto.PubkeyToAddress(ecdsaKey.PublicKey)
	return addr.Hex(), hex.EncodeToString(crypto.FromECDSA(ecdsaKey)), nil
}

// GenerateDiceMnemonic 基于 50 次骰子随机结果生成 128 位熵，并输出 12 个 BIP39 助记词等信息。
func GenerateDiceMnemonic() (*DiceMnemonicResult, error) {
	const (
		numDice         = 50
		entropyBitSize  = 128
		bip39Passphrase = ""
	)

	entropyBytes, dice, err := generateEntropyFromDice(numDice, entropyBitSize)
	if err != nil {
		return nil, fmt.Errorf("生成熵失败: %w", err)
	}

	diceStr := make([]string, len(dice))
	for i, d := range dice {
		diceStr[i] = fmt.Sprintf("%d", d)
	}
	diceText := strings.Join(diceStr, " ")

	entropyBin := bigIntToBinStr(new(big.Int).SetBytes(entropyBytes), entropyBitSize)

	h := sha256.Sum256(entropyBytes)
	hashBin := bigIntToBinStr(new(big.Int).SetBytes(h[:]), 256)
	checksumBits := entropyBitSize / 32
	checksum := hashBin[:checksumBits]
	combined := entropyBin + checksum

	mnemonic, err := bip39.NewMnemonic(entropyBytes)
	if err != nil {
		return nil, fmt.Errorf("生成助记词失败: %w", err)
	}

	seed := bip39.NewSeed(mnemonic, bip39Passphrase)

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("生成主扩展密钥失败: %w", err)
	}

	const hardened = hdkeychain.HardenedKeyStart

	btcPath := []uint32{44 + hardened, 0 + hardened, 0 + hardened, 0, 0}
	btcKey, err := deriveChild(masterKey, btcPath)
	if err != nil {
		return nil, fmt.Errorf("派生 BTC 扩展密钥失败: %w", err)
	}
	btcAddr, btcWIF, err := btcAddressFromKey(btcKey)
	if err != nil {
		return nil, fmt.Errorf("生成 BTC 地址失败: %w", err)
	}

	ethPath := []uint32{44 + hardened, 60 + hardened, 0 + hardened, 0, 0}
	ethKey, err := deriveChild(masterKey, ethPath)
	if err != nil {
		return nil, fmt.Errorf("派生 ETH 扩展密钥失败: %w", err)
	}
	ethAddr, ethPrivHex, err := ethAddressFromKey(ethKey)
	if err != nil {
		return nil, fmt.Errorf("生成 ETH 地址失败: %w", err)
	}

	lines := []string{
		fmt.Sprintf("接受的骰子序列: %s", diceText),
		fmt.Sprintf("熵 (bin,%d位): %s", entropyBitSize, entropyBin),
		fmt.Sprintf("校验和: %s", checksum),
		fmt.Sprintf("拼接后 (%d位): %s", len(combined), combined),
		"助记词 (12 个):",
		mnemonic,
		fmt.Sprintf("BIP39 种子 (hex, 无额外口令): %x", seed),
		"请在离线安全环境中运行，并考虑设置额外 BIP39 口令。",
		fmt.Sprintf("BTC 地址 (m/44'/0'/0'/0/0): %s", btcAddr),
		fmt.Sprintf("BTC 私钥 (WIF, compressed): %s", btcWIF),
		fmt.Sprintf("ETH 地址 (m/44'/60'/0'/0/0): %s", ethAddr),
		fmt.Sprintf("ETH 私钥 (hex): %s", ethPrivHex),
		fmt.Sprintf("USDT (ERC20/主网与 ETH 地址一致): %s", ethAddr),
	}

	result := &DiceMnemonicResult{
		Dice:              dice,
		DiceText:          diceText,
		EntropyBits:       entropyBin,
		ChecksumBits:      checksum,
		CombinedBits:      combined,
		Mnemonic:          mnemonic,
		MnemonicWords:     strings.Fields(mnemonic),
		SeedHex:           fmt.Sprintf("%x", seed),
		BTCAddress:        btcAddr,
		BTCWIF:            btcWIF,
		ETHAddress:        ethAddr,
		ETHPrivateHex:     ethPrivHex,
		USDTAddress:       ethAddr,
		OutputLines:       lines,
		NumDice:           numDice,
		EntropyBitLength:  entropyBitSize,
		ChecksumBitLength: checksumBits,
	}

	return result, nil
}
