package main

import (
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/tyler-smith/go-bip39"
)

func main() {
	outPath := flag.String("out", "wordlist_shuffled.csv", "输出CSV文件路径")
	flag.Parse()

	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		fmt.Fprintln(os.Stderr, "词表长度异常")
		os.Exit(1)
	}

	shuffled := make([]string, len(wordList))
	copy(shuffled, wordList)

	if err := shuffleStrings(shuffled); err != nil {
		fmt.Fprintln(os.Stderr, "随机乱序失败")
		os.Exit(1)
	}

	if err := writeCSV128x16(*outPath, shuffled); err != nil {
		fmt.Fprintln(os.Stderr, "写入CSV失败")
		os.Exit(1)
	}

	fmt.Println("已生成乱序CSV文件")
	fmt.Println(*outPath)
}

func shuffleStrings(items []string) error {
	// Fisher-Yates shuffle using crypto/rand for unbiased randomness.
	for i := len(items) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(n.Int64())
		items[i], items[j] = items[j], items[i]
	}
	return nil
}

func writeCSV128x16(path string, items []string) error {
	const (
		rows = 16
		cols = 128
	)
	if len(items) != rows*cols {
		return fmt.Errorf("词表数量不匹配")
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	for r := 0; r < rows; r++ {
		start := r * cols
		record := items[start : start+cols]
		if err := w.Write(record); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
