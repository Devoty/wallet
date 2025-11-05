package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
)

const (
	argonTime        uint32 = 3
	argonMemoryKB    uint32 = 64 * 1024
	argonParallelism uint8  = 1
	argonKeyLength   uint32 = 32
	saltSize                = 16
	nonceSize               = 12
)

type kdfParams struct {
	Time        uint32 `json:"time"`
	MemoryKB    uint32 `json:"memory_kb"`
	Parallelism uint8  `json:"parallelism"`
}

type shareEnvelope struct {
	Version    int       `json:"version"`
	ShareIndex int       `json:"share_index"`
	KDF        string    `json:"kdf"`
	KDFParams  kdfParams `json:"kdf_params"`
	Salt       string    `json:"salt"`
	Nonce      string    `json:"nonce"`
	Cipher     string    `json:"cipher"`
	Ciphertext string    `json:"ciphertext"`
	Threshold  int       `json:"threshold,omitempty"`
}

type secretShare struct {
	Index int
	Data  []byte
}

// splitSecret 使用 Shamir 秘密共享算法将原始秘密分成多个分片。
func splitSecret(secret []byte, total, threshold int) ([]secretShare, error) {
	if total <= 0 {
		return nil, errors.New("总分片数量必须大于 0")
	}
	if threshold <= 0 {
		return nil, errors.New("恢复所需分片数量必须大于 0")
	}
	if threshold > total {
		return nil, errors.New("恢复所需分片数量不能大于总分片数量")
	}
	if len(secret) == 0 {
		return nil, errors.New("待分片的秘密内容不能为空")
	}

	rawShares, err := shamir.Split(secret, total, threshold)
	if err != nil {
		return nil, fmt.Errorf("使用 Shamir 分片失败: %w", err)
	}

	shares := make([]secretShare, len(rawShares))
	for i, part := range rawShares {
		if len(part) == 0 {
			return nil, fmt.Errorf("分片 %d 内容为空", i+1)
		}
		shareBytes := make([]byte, len(part))
		copy(shareBytes, part)
		shares[i] = secretShare{
			Index: int(shareBytes[len(shareBytes)-1]),
			Data:  shareBytes,
		}
		if shares[i].Index <= 0 {
			return nil, fmt.Errorf("分片 %d 的索引无效", i+1)
		}
	}

	return shares, nil
}

func shareToMnemonic(share []byte) (string, error) {
	if len(share) == 0 {
		return "", errors.New("分片内容为空，无法转换成助记词")
	}

	// 4 字节前缀存储原始分片长度，确保可逆
	payload := make([]byte, 4+len(share))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(share)))
	copy(payload[4:], share)

	words := encodeBytesToWords(payload)
	return strings.Join(words, " "), nil
}

func mnemonicToShare(mnemonic string) ([]byte, error) {
	trimmed := strings.TrimSpace(mnemonic)
	if trimmed == "" {
		return nil, errors.New("助记词内容为空")
	}

	words := strings.Fields(trimmed)
	data, err := decodeWordsToBytes(words)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, errors.New("助记词解析失败: 数据长度不足")
	}

	length := binary.BigEndian.Uint32(data[:4])
	if int(length) > len(data)-4 {
		return nil, fmt.Errorf("助记词解析失败: 长度字段不匹配 (期望 %d, 实际 %d)", length, len(data)-4)
	}

	share := make([]byte, length)
	copy(share, data[4:4+length])
	return share, nil
}

func encodeBytesToWords(data []byte) []string {
	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		panic("bip39 词表长度异常")
	}

	var (
		words   []string
		acc     uint32
		bitSize int
	)

	for _, b := range data {
		acc = (acc << 8) | uint32(b)
		bitSize += 8

		for bitSize >= 11 {
			index := (acc >> uint(bitSize-11)) & 0x7FF
			words = append(words, wordList[index])
			bitSize -= 11
			acc &= (1 << uint(bitSize)) - 1
		}
	}

	if bitSize > 0 {
		index := (acc << uint(11-bitSize)) & 0x7FF
		words = append(words, wordList[index])
	}

	return words
}

func decodeWordsToBytes(words []string) ([]byte, error) {
	var (
		data    []byte
		acc     uint32
		bitSize int
	)

	for _, word := range words {
		index, ok := bip39.GetWordIndex(word)
		if !ok {
			return nil, fmt.Errorf("未知助记词: %s", word)
		}
		acc = (acc << 11) | uint32(index)
		bitSize += 11

		for bitSize >= 8 {
			bitSize -= 8
			byteVal := byte((acc >> uint(bitSize)) & 0xFF)
			data = append(data, byteVal)
			acc &= (1 << uint(bitSize)) - 1
		}
	}

	return data, nil
}

func reconstructSecret(shares []secretShare) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("至少需要提供一个分片")
	}

	parts := make([][]byte, len(shares))
	seen := make(map[int]struct{}, len(shares))

	for i, share := range shares {
		if len(share.Data) == 0 {
			return nil, fmt.Errorf("分片 #%d 内容为空", share.Index)
		}
		if share.Index <= 0 || share.Index > 255 {
			return nil, fmt.Errorf("分片编号 %d 无效", share.Index)
		}
		if _, ok := seen[share.Index]; ok {
			return nil, fmt.Errorf("检测到重复的分片编号 %d", share.Index)
		}
		seen[share.Index] = struct{}{}

		part := make([]byte, len(share.Data))
		copy(part, share.Data)

		if part[len(part)-1] != byte(share.Index) {
			return nil, fmt.Errorf("分片 #%d 数据内的索引与元数据不匹配", share.Index)
		}
		parts[i] = part
	}

	secret, err := shamir.Combine(parts)
	if err != nil {
		return nil, fmt.Errorf("Shamir 分片恢复失败: %w", err)
	}
	return secret, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "请指定 encrypt、decrypt、split 或 serve 子命令。")
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "encrypt":
		err = runEncrypt(os.Args[2:])
	case "decrypt":
		err = runDecrypt(os.Args[2:])
	case "split":
		err = runSplit(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("用法示例：")
	fmt.Println("  go run main.go encrypt -in share1.txt -out share1.json -index 1 -password \"your_password\"")
	fmt.Println("  go run main.go decrypt -in share1.json -out share1.dec -password \"your_password\"")
	fmt.Println("  go run main.go split -in secret.bin -out-dir shares -password \"your_password\" -shares 5 -threshold 3")
	fmt.Println("  go run main.go serve -addr :8080")
}

func runSplit(args []string) error {
	flagSet := flag.NewFlagSet("split", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	inPath := flagSet.String("in", "", "输入原始秘密文件路径")
	outDir := flagSet.String("out-dir", "", "输出加密分片目录")
	password := flagSet.String("password", "", "主口令")
	totalShares := flagSet.Int("shares", 0, "总分片数量 (>= 2)")
	thresholdFlag := flagSet.Int("threshold", 0, "恢复所需的分片数量 (默认等于总分片数)")

	if err := flagSet.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		return errors.New("请使用 -in 指定输入文件")
	}
	if *outDir == "" {
		return errors.New("请使用 -out-dir 指定输出目录")
	}
	if *password == "" {
		return errors.New("请使用 -password 指定主口令")
	}
	if *totalShares < 2 {
		return errors.New("请使用 -shares 指定有效的分片数量 (>= 2)")
	}

	threshold := *thresholdFlag
	if threshold == 0 {
		threshold = *totalShares
	}
	if threshold < 2 {
		return errors.New("恢复所需分片数量必须大于等于 2")
	}
	if threshold > *totalShares {
		return errors.New("恢复所需的分片数量不能大于总分片数量")
	}

	secret, err := os.ReadFile(*inPath)
	if err != nil {
		return fmt.Errorf("读取输入文件失败: %w", err)
	}

	shares, err := splitSecret(secret, *totalShares, threshold)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	sort.Slice(shares, func(i, j int) bool {
		return shares[i].Index < shares[j].Index
	})

	for _, share := range shares {
		mnemonic, err := shareToMnemonic(share.Data)
		if err != nil {
			return fmt.Errorf("分片 #%d 转换助记词失败: %w", share.Index, err)
		}

		env, err := encryptShare(*password, share.Index, []byte(mnemonic))
		if err != nil {
			return err
		}
		env.Threshold = threshold
		payload, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return fmt.Errorf("序列化 JSON 失败: %w", err)
		}
		outPath := filepath.Join(*outDir, fmt.Sprintf("share_%d.json", share.Index))
		if err := os.WriteFile(outPath, payload, 0o600); err != nil {
			return fmt.Errorf("写入分片文件失败: %w", err)
		}
	}

	fmt.Printf("✅ 已生成 %d 个分片，输出目录: %s\n", len(shares), *outDir)
	fmt.Println("🔑 每个 JSON 分片内包含 share_index，可使用 decrypt 子命令恢复对应的助记词分片。")
	return nil
}

func runEncrypt(args []string) error {
	flagSet := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	inPath := flagSet.String("in", "", "输入分片文件路径")
	outPath := flagSet.String("out", "", "输出加密文件路径")
	index := flagSet.Int("index", 0, "分片编号 (>=1)")
	password := flagSet.String("password", "", "主口令")

	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if *inPath == "" {
		return errors.New("请使用 -in 指定输入文件")
	}
	if *outPath == "" {
		return errors.New("请使用 -out 指定输出文件")
	}
	if *index <= 0 {
		return errors.New("请使用 -index 指定有效的分片编号 (>= 1)")
	}
	if *password == "" {
		return errors.New("请使用 -password 指定主口令")
	}

	plaintext, err := os.ReadFile(*inPath)
	if err != nil {
		return fmt.Errorf("读取输入文件失败: %w", err)
	}

	env, err := encryptShare(*password, *index, plaintext)
	if err != nil {
		return err
	}

	// 将加密元数据与密文序列化为 JSON
	payload, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败: %w", err)
	}

	if err := os.WriteFile(*outPath, payload, 0o600); err != nil {
		return fmt.Errorf("写入输出文件失败: %w", err)
	}

	fmt.Printf("✅ 加密完成: %s\n", *outPath)
	return nil
}

func runDecrypt(args []string) error {
	flagSet := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	inPath := flagSet.String("in", "", "输入加密 JSON 文件路径")
	outPath := flagSet.String("out", "", "输出解密文件路径")
	password := flagSet.String("password", "", "主口令")

	if err := flagSet.Parse(args); err != nil {
		return err
	}

	if *inPath == "" {
		return errors.New("请使用 -in 指定输入文件")
	}
	if *outPath == "" {
		return errors.New("请使用 -out 指定输出文件")
	}
	if *password == "" {
		return errors.New("请使用 -password 指定主口令")
	}

	data, err := os.ReadFile(*inPath)
	if err != nil {
		return fmt.Errorf("读取输入文件失败: %w", err)
	}

	var env shareEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("解析 JSON 失败: %w", err)
	}

	if env.Version != 1 {
		return fmt.Errorf("不支持的加密文件版本: %d", env.Version)
	}
	if env.ShareIndex <= 0 {
		return errors.New("JSON 中缺少有效的 share_index 字段")
	}
	if env.Cipher != "AES-GCM" {
		return fmt.Errorf("不支持的加密算法: %s", env.Cipher)
	}
	if env.KDF != "argon2id" {
		return fmt.Errorf("不支持的 KDF: %s", env.KDF)
	}

	salt, err := hex.DecodeString(env.Salt)
	if err != nil {
		return fmt.Errorf("解析 salt 失败: %w", err)
	}
	if len(salt) != saltSize {
		return fmt.Errorf("salt 长度不正确，期望 %d 字节，实际 %d", saltSize, len(salt))
	}

	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return fmt.Errorf("解析 nonce 失败: %w", err)
	}
	if len(nonce) != nonceSize {
		return fmt.Errorf("nonce 长度不正确，期望 %d 字节，实际 %d", nonceSize, len(nonce))
	}

	cipherBytes, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		return fmt.Errorf("解析 ciphertext 失败: %w", err)
	}
	if len(cipherBytes) == 0 {
		return errors.New("ciphertext 字段为空")
	}

	// 使用 Argon2id 恢复分片密钥
	plaintext, err := decryptShare(*password, env, salt, nonce, cipherBytes)
	if err != nil {
		return err
	}

	mnemonic := strings.TrimSpace(string(plaintext))
	shareBytes, err := mnemonicToShare(mnemonic)
	if err != nil {
		return fmt.Errorf("助记词解析失败: %w", err)
	}
	if len(shareBytes) == 0 {
		return errors.New("助记词对应的分片为空")
	}
	if shareBytes[len(shareBytes)-1] != byte(env.ShareIndex) {
		return fmt.Errorf("助记词中的索引与 share_index 不匹配 (%d != %d)", shareBytes[len(shareBytes)-1], env.ShareIndex)
	}

	if err := os.WriteFile(*outPath, []byte(mnemonic), 0o600); err != nil {
		return fmt.Errorf("写入输出文件失败: %w", err)
	}

	fmt.Printf("✅ 解密完成: %s\n", *outPath)
	fmt.Println("🔑 分片助记词内容:")
	fmt.Println(mnemonic)
	return nil
}

// deriveKey 使用 Argon2id 根据主口令和分片编号生成密钥
func deriveKey(password string, index int, salt []byte) []byte {
	input := password + "-share-" + strconv.Itoa(index)
	return argon2.IDKey([]byte(input), salt, argonTime, argonMemoryKB, argonParallelism, argonKeyLength)
}

func encryptShare(password string, index int, plaintext []byte) (shareEnvelope, error) {
	if index <= 0 {
		return shareEnvelope{}, errors.New("分片编号必须大于等于 1")
	}
	if password == "" {
		return shareEnvelope{}, errors.New("主口令不能为空")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return shareEnvelope{}, fmt.Errorf("生成盐值失败: %w", err)
	}

	// 使用 Argon2id 从主口令派生分片密钥
	key := deriveKey(password, index, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return shareEnvelope{}, fmt.Errorf("初始化 AES 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return shareEnvelope{}, fmt.Errorf("初始化 AES-GCM 失败: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return shareEnvelope{}, fmt.Errorf("生成随机 nonce 失败: %w", err)
	}

	// 使用 AES-GCM 加密分片内容
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := shareEnvelope{
		Version:    1,
		ShareIndex: index,
		KDF:        "argon2id",
		KDFParams: kdfParams{
			Time:        argonTime,
			MemoryKB:    argonMemoryKB,
			Parallelism: argonParallelism,
		},
		Salt:       hex.EncodeToString(salt),
		Nonce:      hex.EncodeToString(nonce),
		Cipher:     "AES-GCM",
		Ciphertext: hex.EncodeToString(ciphertext),
	}
	return env, nil
}

func decryptShare(password string, env shareEnvelope, salt, nonce, cipherBytes []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("主口令不能为空")
	}
	key := deriveKey(password, env.ShareIndex, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES-GCM 失败: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce 长度与 AES-GCM 要求不匹配: 期望 %d，实际 %d", gcm.NonceSize(), len(nonce))
	}

	// 使用 AES-GCM 解密获取原始分片
	plaintext, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}
	return plaintext, nil
}

func runServe(args []string) error {
	flagSet := flag.NewFlagSet("serve", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	addr := flagSet.String("addr", "localhost:8081", "HTTP 服务监听地址")

	if err := flagSet.Parse(args); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndexPage)
	mux.HandleFunc("/api/encrypt", handleAPIEncrypt)
	mux.HandleFunc("/api/decrypt", handleAPIDecrypt)
	mux.HandleFunc("/api/split", handleAPISplit)
	mux.HandleFunc("/api/restore", handleAPIRestore)

	fmt.Printf("🔐 Web 服务启动，访问 http://%s\n", *addr)
	if err := http.ListenAndServe(*addr, logRequest(mux)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("启动 HTTP 服务失败: %w", err)
	}
	return nil
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

const indexPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>分片加密解密工具</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#f5f6fa; margin:0; padding:0; color:#1f2933; }
    header { background:#1f2933; color:#fff; padding:16px 24px; }
    main { max-width:960px; margin:32px auto; background:#fff; border-radius:12px; box-shadow:0 12px 35px rgba(15,23,42,0.12); padding:32px; }
    h1 { margin:0 0 8px; font-size:1.8rem; }
    .tabs { display:flex; gap:12px; margin-bottom:24px; }
    .tab { flex:1; padding:12px; text-align:center; border-radius:8px; cursor:pointer; border:1px solid #cfd8e3; background:#f8fafc; transition:all .2s ease; font-weight:600; }
    .tab.active { background:#2563eb; color:#fff; border-color:#2563eb; box-shadow:0 10px 25px rgba(37,99,235,0.3); }
    form { display:none; flex-direction:column; gap:16px; }
    form.active { display:flex; }
    label { font-weight:600; }
    textarea, input { font:inherit; padding:10px 12px; border-radius:8px; border:1px solid #cbd5f5; transition:border .2s ease; resize:vertical; }
    textarea:focus, input:focus { outline:none; border-color:#2563eb; box-shadow:0 0 0 3px rgba(37,99,235,0.15); }
    button { padding:12px; border:none; border-radius:8px; background:#2563eb; color:#fff; font-size:1rem; cursor:pointer; transition:background .2s ease, transform .1s ease; font-weight:600; }
    button:hover { background:#1d4ed8; }
    button:active { transform:scale(0.98); }
    pre { background:#0f172a; color:#e2e8f0; padding:16px; border-radius:8px; overflow:auto; font-size:0.95rem; }
    .share-list { display:flex; flex-direction:column; gap:16px; }
    .share-block { background:#f8fafc; border:1px solid #cbd5f5; border-radius:10px; padding:16px; }
    .share-block h4 { margin:0 0 12px; font-size:1.05rem; color:#1f2933; }
    .share-input-list { display:flex; flex-direction:column; gap:12px; margin-bottom:12px; }
    .share-input-block { display:flex; flex-direction:column; gap:8px; border:1px dashed #cbd5f5; background:#f8fafc; border-radius:10px; padding:12px; }
    .share-input-block textarea { min-height:100px; }
    .secondary-btn { background:#e2e8f0; color:#1f2933; border:1px solid #cbd5f5; }
    .secondary-btn:hover { background:#cbd5f5; }
    .share-input-block .secondary-btn { align-self:flex-end; }
    .result, .error { border-radius:8px; padding:12px 16px; font-weight:600; }
    .result { background:#ecfdf5; color:#047857; border:1px solid #6ee7b7; }
    .error { background:#fef2f2; color:#b91c1c; border:1px solid #fecaca; }
  </style>
</head>
<body>
  <header>
    <h1>分片加密解密工具</h1>
    <p>基于 Argon2id + AES-GCM 的安全加密，适用于 Shamir 分片。</p>
  </header>
  <main>
    <div class="tabs">
      <div class="tab active" data-target="split">分片并加密</div>
      <div class="tab" data-target="restore">恢复原文</div>
      <div class="tab" data-target="encrypt">单份加密</div>
      <div class="tab" data-target="decrypt">解密分片</div>
    </div>

    <form id="split-form" class="active">
      <div>
        <label for="split-secret">原文内容</label>
        <textarea id="split-secret" rows="6" placeholder="粘贴需要保护的原文内容"></textarea>
      </div>
      <div>
        <label for="split-password">主口令</label>
        <input id="split-password" type="password" placeholder="输入主口令" />
      </div>
      <div>
        <label for="split-shares">总分片数量</label>
        <input id="split-shares" type="number" min="2" value="3" />
      </div>
      <div>
        <label for="split-threshold">恢复门限 (可选)</label>
        <input id="split-threshold" type="number" min="2" placeholder="默认等于总分片数量" />
      </div>
      <button type="submit">生成分片并加密</button>
      <div id="split-message"></div>
      <div id="split-result" class="share-list" style="display:none;"></div>
    </form>

    <form id="restore-form">
      <div>
        <label>加密分片 JSON</label>
        <div id="restore-share-list" class="share-input-list"></div>
        <button type="button" id="restore-add-share" class="secondary-btn">添加分片输入</button>
      </div>
      <div>
        <label for="restore-password">主口令</label>
        <input id="restore-password" type="password" placeholder="输入主口令" />
      </div>
      <button type="submit">恢复原文</button>
      <div id="restore-message"></div>
      <pre id="restore-result" style="display:none;"></pre>
    </form>

    <form id="encrypt-form">
      <div>
        <label for="encrypt-content">分片内容</label>
        <textarea id="encrypt-content" rows="6" placeholder="粘贴分片明文内容"></textarea>
      </div>
      <div>
        <label for="encrypt-index">分片编号</label>
        <input id="encrypt-index" type="number" min="1" value="1" />
      </div>
      <div>
        <label for="encrypt-password">主口令</label>
        <input id="encrypt-password" type="password" placeholder="输入主口令" />
      </div>
      <button type="submit">执行加密</button>
      <div id="encrypt-message"></div>
      <pre id="encrypt-result" style="display:none;"></pre>
    </form>

    <form id="decrypt-form">
      <div>
        <label for="decrypt-json">加密 JSON</label>
        <textarea id="decrypt-json" rows="6" placeholder="粘贴 shareX.json 文件内容"></textarea>
      </div>
      <div>
        <label for="decrypt-password">主口令</label>
        <input id="decrypt-password" type="password" placeholder="输入主口令" />
      </div>
      <button type="submit">执行解密</button>
      <div id="decrypt-message"></div>
      <pre id="decrypt-result" style="display:none;"></pre>
    </form>
  </main>

  <script>
    const tabs = document.querySelectorAll('.tab');
    const forms = {
      split: document.getElementById('split-form'),
      restore: document.getElementById('restore-form'),
      encrypt: document.getElementById('encrypt-form'),
      decrypt: document.getElementById('decrypt-form')
    };

    tabs.forEach(tab => tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      Object.entries(forms).forEach(([name, form]) => {
        form.classList.toggle('active', name === tab.dataset.target);
      });
    }));

    function showMessage(box, type, text) {
      box.textContent = text;
      box.className = type === 'error' ? 'error' : 'result';
    }

    document.getElementById('split-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const secret = document.getElementById('split-secret').value;
      const password = document.getElementById('split-password').value;
      const sharesValue = document.getElementById('split-shares').value;
      const sharesParsed = Number.parseInt(sharesValue, 10);
      const shares = Number.isFinite(sharesParsed) ? sharesParsed : 0;
      const thresholdRaw = document.getElementById('split-threshold').value;
      const thresholdParsed = thresholdRaw ? Number.parseInt(thresholdRaw, 10) : 0;
      const threshold = Number.isFinite(thresholdParsed) ? thresholdParsed : 0;
      const messageBox = document.getElementById('split-message');
      const resultBox = document.getElementById('split-result');

      resultBox.style.display = 'none';
      resultBox.innerHTML = '';
      messageBox.textContent = '';
      messageBox.className = '';

      try {
        const res = await fetch('/api/split', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret, password, shares, threshold })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || '分片加密失败');
        if (!Array.isArray(data.shares)) throw new Error('服务返回数据异常');

        showMessage(messageBox, 'success', '✅ 已生成 ' + data.shares.length + ' 个加密分片：');
        data.shares.forEach(item => {
          const block = document.createElement('div');
          block.className = 'share-block';
          const title = document.createElement('h4');
          title.textContent = '分片 #' + item.share_index;
          const pre = document.createElement('pre');
          pre.textContent = item.pretty_json;
          block.appendChild(title);
          block.appendChild(pre);
          resultBox.appendChild(block);
        });
        resultBox.style.display = 'flex';
      } catch (err) {
        showMessage(messageBox, 'error', '❌ ' + err.message);
      }
    });

    const restoreList = document.getElementById('restore-share-list');
    const restoreAddBtn = document.getElementById('restore-add-share');

    function createRestoreInput(defaultValue = '') {
      const wrapper = document.createElement('div');
      wrapper.className = 'share-input-block';
      const textarea = document.createElement('textarea');
      textarea.placeholder = '粘贴 shareX.json 内容';
      textarea.value = defaultValue;
      wrapper.appendChild(textarea);
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'secondary-btn';
      removeBtn.textContent = '删除';
      removeBtn.addEventListener('click', () => {
        const blocks = restoreList.querySelectorAll('.share-input-block');
        if (blocks.length <= 1) {
          textarea.value = '';
          return;
        }
        restoreList.removeChild(wrapper);
      });
      wrapper.appendChild(removeBtn);
      restoreList.appendChild(wrapper);
    }

    restoreAddBtn.addEventListener('click', () => createRestoreInput());
    if (restoreList.childElementCount === 0) {
      for (let i = 0; i < 3; i += 1) {
        createRestoreInput();
      }
    }

    document.getElementById('restore-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('restore-password').value;
      const messageBox = document.getElementById('restore-message');
      const resultBox = document.getElementById('restore-result');
      const shares = Array.from(restoreList.querySelectorAll('textarea'))
        .map(area => area.value.trim())
        .filter(text => text.length > 0);

      resultBox.style.display = 'none';
      resultBox.textContent = '';
      messageBox.textContent = '';
      messageBox.className = '';

      if (shares.length === 0) {
        showMessage(messageBox, 'error', '请至少输入一个分片 JSON');
        return;
      }
      if (!password) {
        showMessage(messageBox, 'error', '主口令不能为空');
        return;
      }

      try {
        const res = await fetch('/api/restore', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ shares, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || '恢复失败');

        let info = '✅ 恢复成功';
        if (data.threshold) {
          info += '（门限 ' + data.threshold + '）';
        }
        if (Array.isArray(data.used_indices) && data.used_indices.length > 0) {
          info += '，使用分片 #' + data.used_indices.join(', ');
        }
        info += '。';

        showMessage(messageBox, 'success', info);
        resultBox.textContent = data.secret || '';
        resultBox.style.display = 'block';
      } catch (err) {
        showMessage(messageBox, 'error', '❌ ' + err.message);
      }
    });

    document.getElementById('encrypt-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const content = document.getElementById('encrypt-content').value;
      const index = Number(document.getElementById('encrypt-index').value);
      const password = document.getElementById('encrypt-password').value;
      const messageBox = document.getElementById('encrypt-message');
      const resultBox = document.getElementById('encrypt-result');

      resultBox.style.display = 'none';
      messageBox.textContent = '';
      messageBox.className = '';

      try {
        const res = await fetch('/api/encrypt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content, index, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || '加密失败');
        showMessage(messageBox, 'success', '✅ 加密成功，结果如下：');
        resultBox.textContent = data.pretty_json;
        resultBox.style.display = 'block';
      } catch (err) {
        showMessage(messageBox, 'error', '❌ ' + err.message);
      }
    });

    document.getElementById('decrypt-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = document.getElementById('decrypt-json').value;
      const password = document.getElementById('decrypt-password').value;
      const messageBox = document.getElementById('decrypt-message');
      const resultBox = document.getElementById('decrypt-result');

      resultBox.style.display = 'none';
      messageBox.textContent = '';
      messageBox.className = '';

      try {
        const res = await fetch('/api/decrypt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ payload, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || '解密失败');
        showMessage(messageBox, 'success', '✅ 解密成功，原文如下：');
        resultBox.textContent = data.plaintext;
        resultBox.style.display = 'block';
      } catch (err) {
        showMessage(messageBox, 'error', '❌ ' + err.message);
      }
    });
  </script>
</body>
</html>`

func handleIndexPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexPageHTML)
}

type apiEncryptRequest struct {
	Content  string `json:"content"`
	Index    int    `json:"index"`
	Password string `json:"password"`
}

type apiEncryptResponse struct {
	Envelope   shareEnvelope `json:"envelope"`
	PrettyJSON string        `json:"pretty_json"`
}

type apiSplitRequest struct {
	Secret    string `json:"secret"`
	Password  string `json:"password"`
	Shares    int    `json:"shares"`
	Threshold int    `json:"threshold"`
}

type splitShareResponse struct {
	ShareIndex int           `json:"share_index"`
	Envelope   shareEnvelope `json:"envelope"`
	PrettyJSON string        `json:"pretty_json"`
}

type apiSplitResponse struct {
	Shares []splitShareResponse `json:"shares"`
}

type apiDecryptRequest struct {
	Payload  string `json:"payload"`
	Password string `json:"password"`
}

type apiDecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

type apiRestoreRequest struct {
	Shares   []string `json:"shares"`
	Password string   `json:"password"`
}

type apiRestoreResponse struct {
	Secret      string `json:"secret"`
	Threshold   int    `json:"threshold,omitempty"`
	UsedIndices []int  `json:"used_indices"`
}

func handleAPISplit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req apiSplitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("请求数据解析失败: %w", err))
		return
	}

	if req.Secret == "" {
		writeAPIError(w, http.StatusBadRequest, errors.New("待分片的秘密内容不能为空"))
		return
	}
	if req.Password == "" {
		writeAPIError(w, http.StatusBadRequest, errors.New("主口令不能为空"))
		return
	}
	if req.Shares < 2 {
		writeAPIError(w, http.StatusBadRequest, errors.New("分片数量必须大于等于 2"))
		return
	}

	threshold := req.Threshold
	if threshold == 0 {
		threshold = req.Shares
	}
	if threshold < 2 {
		writeAPIError(w, http.StatusBadRequest, errors.New("恢复门限必须大于等于 2"))
		return
	}
	if threshold > req.Shares {
		writeAPIError(w, http.StatusBadRequest, errors.New("恢复门限不能大于分片数量"))
		return
	}

	shares, err := splitSecret([]byte(req.Secret), req.Shares, threshold)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("生成分片失败: %w", err))
		return
	}

	respShares := make([]splitShareResponse, 0, len(shares))
	for _, share := range shares {
		encoded := hex.EncodeToString(share.Data)
		env, err := encryptShare(req.Password, share.Index, []byte(encoded))
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("加密分片 %d 失败: %w", share.Index, err))
			return
		}
		env.Threshold = threshold
		pretty, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("格式化分片 %d 失败: %w", share.Index, err))
			return
		}
		respShares = append(respShares, splitShareResponse{
			ShareIndex: share.Index,
			Envelope:   env,
			PrettyJSON: string(pretty),
		})
	}

	writeAPISuccess(w, apiSplitResponse{Shares: respShares})
}

func handleAPIEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req apiEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("请求数据解析失败: %w", err))
		return
	}
	if req.Content == "" {
		writeAPIError(w, http.StatusBadRequest, errors.New("分片内容不能为空"))
		return
	}

	env, err := encryptShare(req.Password, req.Index, []byte(req.Content))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}

	pretty, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("序列化 JSON 失败: %w", err))
		return
	}

	writeAPISuccess(w, apiEncryptResponse{
		Envelope:   env,
		PrettyJSON: string(pretty),
	})
}

func handleAPIDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req apiDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("请求数据解析失败: %w", err))
		return
	}
	if req.Payload == "" {
		writeAPIError(w, http.StatusBadRequest, errors.New("加密 JSON 内容不能为空"))
		return
	}

	var env shareEnvelope
	if err := json.Unmarshal([]byte(req.Payload), &env); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("解析加密 JSON 失败: %w", err))
		return
	}

	if env.Version != 1 {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("不支持的加密文件版本: %d", env.Version))
		return
	}
	if env.ShareIndex <= 0 {
		writeAPIError(w, http.StatusBadRequest, errors.New("share_index 字段无效"))
		return
	}
	if env.Cipher != "AES-GCM" || env.KDF != "argon2id" {
		writeAPIError(w, http.StatusBadRequest, errors.New("加密元数据不受支持"))
		return
	}

	salt, err := hex.DecodeString(env.Salt)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("解析 salt 失败: %w", err))
		return
	}
	if len(salt) != saltSize {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("salt 长度不正确，期望 %d 字节，实际 %d", saltSize, len(salt)))
		return
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("解析 nonce 失败: %w", err))
		return
	}
	if len(nonce) != nonceSize {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("nonce 长度不正确，期望 %d 字节，实际 %d", nonceSize, len(nonce)))
		return
	}
	cipherBytes, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("解析 ciphertext 失败: %w", err))
		return
	}
	if len(cipherBytes) == 0 {
		writeAPIError(w, http.StatusBadRequest, errors.New("ciphertext 字段为空"))
		return
	}

	plaintext, err := decryptShare(req.Password, env, salt, nonce, cipherBytes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}

	writeAPISuccess(w, apiDecryptResponse{
		Plaintext: string(plaintext),
	})
}

func handleAPIRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req apiRestoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("请求数据解析失败: %w", err))
		return
	}
	if len(req.Shares) == 0 {
		writeAPIError(w, http.StatusBadRequest, errors.New("请至少提供一个加密分片 JSON"))
		return
	}
	if req.Password == "" {
		writeAPIError(w, http.StatusBadRequest, errors.New("主口令不能为空"))
		return
	}

	seen := make(map[int]struct{})
	shares := make([]secretShare, 0, len(req.Shares))
	usedIndices := make([]int, 0, len(req.Shares))
	expectedThreshold := 0

	for idx, raw := range req.Shares {
		payload := strings.TrimSpace(raw)
		if payload == "" {
			continue
		}
		var env shareEnvelope
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("解析第 %d 个分片 JSON 失败: %w", idx+1, err))
			return
		}
		if env.Version != 1 {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 使用了不支持的版本: %d", env.ShareIndex, env.Version))
			return
		}
		if env.ShareIndex <= 0 {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("第 %d 个分片缺少有效的 share_index", idx+1))
			return
		}
		if _, ok := seen[env.ShareIndex]; ok {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("检测到重复的分片编号: %d", env.ShareIndex))
			return
		}
		seen[env.ShareIndex] = struct{}{}
		usedIndices = append(usedIndices, env.ShareIndex)

		if env.Cipher != "AES-GCM" || env.KDF != "argon2id" {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 的加密参数不受支持", env.ShareIndex))
			return
		}

		salt, err := hex.DecodeString(env.Salt)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 解析 salt 失败: %w", env.ShareIndex, err))
			return
		}
		if len(salt) != saltSize {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 的 salt 长度不正确", env.ShareIndex))
			return
		}
		nonce, err := hex.DecodeString(env.Nonce)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 解析 nonce 失败: %w", env.ShareIndex, err))
			return
		}
		if len(nonce) != nonceSize {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 的 nonce 长度不正确", env.ShareIndex))
			return
		}
		cipherBytes, err := hex.DecodeString(env.Ciphertext)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 解析 ciphertext 失败: %w", env.ShareIndex, err))
			return
		}
		if len(cipherBytes) == 0 {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 的 ciphertext 为空", env.ShareIndex))
			return
		}

		plaintext, err := decryptShare(req.Password, env, salt, nonce, cipherBytes)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 解密失败: %w", env.ShareIndex, err))
			return
		}
		mnemonic := strings.TrimSpace(string(plaintext))
		shareBytes, err := mnemonicToShare(mnemonic)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 助记词解析失败: %w", env.ShareIndex, err))
			return
		}
		if len(shareBytes) == 0 {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 助记词对应内容为空", env.ShareIndex))
			return
		}
		if shareBytes[len(shareBytes)-1] != byte(env.ShareIndex) {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("分片 #%d 助记词索引与 share_index 不一致", env.ShareIndex))
			return
		}

		shares = append(shares, secretShare{
			Index: env.ShareIndex,
			Data:  shareBytes,
		})

		if env.Threshold > 0 {
			if expectedThreshold == 0 {
				expectedThreshold = env.Threshold
			} else if expectedThreshold != env.Threshold {
				writeAPIError(w, http.StatusBadRequest, fmt.Errorf("检测到分片阈值不一致: %d 与 %d", expectedThreshold, env.Threshold))
				return
			}
		}
	}

	if len(shares) == 0 {
		writeAPIError(w, http.StatusBadRequest, errors.New("未提供任何有效分片内容"))
		return
	}
	if expectedThreshold > 0 && len(shares) < expectedThreshold {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("需要至少 %d 个分片才能恢复原文，目前仅提供 %d 个", expectedThreshold, len(shares)))
		return
	}

	secret, err := reconstructSecret(shares)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Errorf("恢复原文失败: %w", err))
		return
	}

	sort.Ints(usedIndices)

	writeAPISuccess(w, apiRestoreResponse{
		Secret:      string(secret),
		Threshold:   expectedThreshold,
		UsedIndices: usedIndices,
	})
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}

func writeAPISuccess(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}
