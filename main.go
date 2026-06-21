// ncmdump —— 单二进制、跨平台、并行的 .ncm 解密工具。
//
// 特性:
//   - 递归扫描目录下所有 .ncm 文件
//   - goroutine 工作池并行解密(默认 = CPU 核数)
//   - 硬件加速:预计算 256 字节周期 keystream + 按机器字(uint64)向量化 XOR
//   - 输出日志同时写到 stdout 与日志文件
//   - 重复文件比较:已存在低音质版本检测 + " (N)" 同曲目去重
//
// 纯标准库,无外部依赖。交叉编译示例:
//
//	GOOS=windows GOARCH=amd64 go build -o ncmdump.exe .
//	GOOS=linux   GOARCH=arm64 go build -o ncmdump-linux-arm64 .
package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// version 由 release 构建通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

var (
	coreKey = mustHex("687A4852416D736F356B496E62617857")
	metaKey = mustHex("2331346C6A6B5F215C5D2630553C2728")
	magic   = []byte("CTENFDAM")
)

const chunkSize = 0x8000 // 32 KiB,是 256 的整数倍 → keystream 在每块内对齐

// ---------- 日志 ----------

type logger struct {
	mu   sync.Mutex
	file *os.File
}

func (l *logger) printf(format string, a ...any) {
	line := fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println(line)
	if l.file != nil {
		fmt.Fprintln(l.file, line)
	}
}

// ---------- 解密核心 ----------

// buildKeyBox 执行 RC4 KSA 变体,返回 256 字节的 key_box。
func buildKeyBox(key []byte) [256]byte {
	var box [256]byte
	for i := range box {
		box[i] = byte(i)
	}
	var c, last, off int
	for i := 0; i < 256; i++ {
		swap := box[i]
		c = (int(swap) + last + int(key[off])) & 0xff
		off = (off + 1) % len(key)
		box[i] = box[c]
		box[c] = swap
		last = c
	}
	return box
}

// buildPad 由 key_box 预计算 256 字节周期 keystream。
func buildPad(box [256]byte) [256]byte {
	var pad [256]byte
	for p := 0; p < 256; p++ {
		j := (p + 1) & 0xff
		pad[p] = box[(int(box[j])+int(box[(int(box[j])+j)&0xff]))&0xff]
	}
	return pad
}

func pkcs7unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("空数据无法去填充")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > len(b) {
		return nil, fmt.Errorf("非法填充长度 %d", n)
	}
	return b[:len(b)-n], nil
}

func ecbDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("密文长度非块大小整数倍")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Decrypt(out[i:], data[i:])
	}
	return out, nil
}

// decryptChunk 对一个数据块原地做 keystream XOR。
// chunkSize 是 256 的整数倍,故块内位置 k 直接用 pad[k&0xff]。
// 以 uint64 为单位批量 XOR(走 SIMD/宽字),尾部不足 8 字节按字节处理。
func decryptChunk(buf []byte, pad *[256]byte) {
	// 预生成与块对齐的 64 位 pad 视图(256 字节 = 32 个 uint64)。
	var pad64 [32]uint64
	for i := range pad64 {
		pad64[i] = binary.LittleEndian.Uint64(pad[i*8 : i*8+8])
	}
	n := len(buf)
	i := 0
	for ; i+8 <= n; i += 8 {
		v := binary.LittleEndian.Uint64(buf[i:])
		v ^= pad64[(i/8)&31]
		binary.LittleEndian.PutUint64(buf[i:], v)
	}
	for ; i < n; i++ {
		buf[i] ^= pad[i&0xff]
	}
}

type meta struct {
	Format string `json:"format"`
}

// decryptFile 解密单个 .ncm,返回输出文件路径。
func decryptFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	read := func(n int) ([]byte, error) {
		b := make([]byte, n)
		_, err := io.ReadFull(f, b)
		return b, err
	}
	readU32 := func() (uint32, error) {
		b, err := read(4)
		if err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint32(b), nil
	}

	// magic 校验
	hdr, err := read(8)
	if err != nil {
		return "", err
	}
	if string(hdr) != string(magic) {
		return "", errors.New("不是有效的 .ncm 文件(magic 不匹配)")
	}
	if _, err := f.Seek(2, io.SeekCurrent); err != nil {
		return "", err
	}

	// RC4 密钥
	keyLen, err := readU32()
	if err != nil {
		return "", err
	}
	keyData, err := read(int(keyLen))
	if err != nil {
		return "", err
	}
	for i := range keyData {
		keyData[i] ^= 0x64
	}
	dec, err := ecbDecrypt(coreKey, keyData)
	if err != nil {
		return "", fmt.Errorf("解密 RC4 密钥失败: %w", err)
	}
	dec, err = pkcs7unpad(dec)
	if err != nil {
		return "", err
	}
	if len(dec) <= 17 {
		return "", errors.New("RC4 密钥过短")
	}
	box := buildKeyBox(dec[17:])
	pad := buildPad(box)

	// 元数据 → 输出格式
	metaLen, err := readU32()
	if err != nil {
		return "", err
	}
	format := "mp3"
	metaRaw, err := read(int(metaLen))
	if err != nil {
		return "", err
	}
	if metaLen > 22 {
		for i := range metaRaw {
			metaRaw[i] ^= 0x63
		}
		b64 := metaRaw[22:]
		enc := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
		nb, err := base64.StdEncoding.Decode(enc, b64)
		if err == nil {
			if pt, err := ecbDecrypt(metaKey, enc[:nb]); err == nil {
				if pt, err := pkcs7unpad(pt); err == nil && len(pt) > 6 {
					var m meta
					if json.Unmarshal(pt[6:], &m) == nil && m.Format != "" {
						format = m.Format
					}
				}
			}
		}
	}

	// 跳过 crc32(4) + 间隙(5) + 封面图
	if _, err := f.Seek(4+5, io.SeekCurrent); err != nil {
		return "", err
	}
	imgSize, err := readU32()
	if err != nil {
		return "", err
	}
	if _, err := f.Seek(int64(imgSize), io.SeekCurrent); err != nil {
		return "", err
	}

	// 流式解密音频
	base := strings.TrimSuffix(filepath.Base(path), ".ncm")
	outPath := filepath.Join(filepath.Dir(path), base+"."+format)
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	bufp := make([]byte, chunkSize)
	for {
		n, err := f.Read(bufp)
		if n > 0 {
			decryptChunk(bufp[:n], &pad)
			if _, werr := out.Write(bufp[:n]); werr != nil {
				return "", werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return outPath, nil
}

// ---------- 重复文件比较 ----------

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return fi.Size()
}

func exists(p string) bool { return fileSize(p) >= 0 }

// existingOutput 返回该 .ncm 已存在的同名 .mp3/.flac 输出(若有)。
func existingOutput(ncm string) string {
	base := strings.TrimSuffix(ncm, ".ncm")
	for _, ext := range []string{".flac", ".mp3"} {
		if exists(base + ext) {
			return base + ext
		}
	}
	return ""
}

var dupRe = regexp.MustCompile(`^(.*)\s\((\d)\)\.(flac|mp3)$`)

// dedupPass 扫描目录,删除与原曲目体积一致的 " (N)" 重复文件。
func dedupPass(dir string, log *logger, apply bool) {
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		m := dupRe.FindStringSubmatch(d.Name())
		if m == nil {
			return nil
		}
		origin := filepath.Join(filepath.Dir(p), strings.TrimSuffix(m[1], " ")+"."+m[3])
		switch {
		case !exists(origin):
			log.printf("[dedup] 疑似重复需手动确认(原曲不存在): %s", d.Name())
		case fileSize(origin) == fileSize(p):
			if apply {
				if err := os.Remove(p); err == nil {
					log.printf("[dedup] 已删除重复文件: %s", d.Name())
				}
			} else {
				log.printf("[dedup] 重复(体积一致,--apply 后删除): %s", d.Name())
			}
		default:
			log.printf("[dedup] 疑似重复需手动确认(体积不同): %s", d.Name())
		}
		return nil
	})
}

// ---------- main ----------

func main() {
	var (
		dir        = flag.String("dir", ".", "扫描 .ncm 的目录")
		workers    = flag.Int("workers", runtime.NumCPU(), "并行 worker 数")
		logPath    = flag.String("log", "", "日志文件路径(默认 <dir>/ncmdump.log)")
		delSrc     = flag.Bool("delete-src", false, "解密成功后删除源 .ncm")
		delLQ      = flag.Bool("delete-lq", false, "已存在低音质版本时删除它并重新解密")
		dedupApply = flag.Bool("dedup-apply", false, "实际删除重复文件(默认仅报告)")
		showVer    = flag.Bool("version", false, "打印版本并退出")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("ncmdump", version)
		return
	}
	if flag.NArg() > 0 { // 允许位置参数指定目录
		*dir = flag.Arg(0)
	}

	lp := *logPath
	if lp == "" {
		lp = filepath.Join(*dir, "ncmdump.log")
	}
	lf, err := os.OpenFile(lp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法打开日志文件:", err)
		os.Exit(1)
	}
	defer lf.Close()
	log := &logger{file: lf}

	// 收集 .ncm
	var files []string
	_ = filepath.WalkDir(*dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".ncm") {
			files = append(files, p)
		}
		return nil
	})

	log.printf("=== ncmdump %s 启动 dir=%s workers=%d 发现 %d 个 .ncm ===", version, *dir, *workers, len(files))

	var (
		jobs            = make(chan string)
		wg              sync.WaitGroup
		okN, skipN, erN atomic.Int64
		start           = time.Now()
	)
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ncm := range jobs {
				name := filepath.Base(ncm)

				// 重复比较:已存在输出?
				if out := existingOutput(ncm); out != "" {
					dup, nc := fileSize(out), fileSize(ncm)
					ratio := float64(dup) / float64(nc)
					if ratio < 0.8 {
						log.printf("[dup] %q 已存在低音质版本 体积比=%.2f", name, ratio)
						if *delLQ {
							if os.Remove(out) == nil {
								log.printf("[dup] 已删除低音质 %s", filepath.Base(out))
							}
						} else {
							log.printf("[skip] %q 保留现有低音质(用 --delete-lq 覆盖)", name)
							skipN.Add(1)
							continue
						}
					} else {
						log.printf("[skip] %q 已存在等质量输出 体积比=%.2f", name, ratio)
						if *delSrc {
							_ = os.Remove(ncm)
						}
						skipN.Add(1)
						continue
					}
				}

				t0 := time.Now()
				out, err := decryptFile(ncm)
				if err != nil {
					log.printf("[err] %q 解密失败: %v", name, err)
					erN.Add(1)
					continue
				}
				ms := time.Since(t0).Seconds() * 1000
				mb := float64(fileSize(out)) / 1e6
				log.printf("[ok] %s → %s %.1fMB %.0fms %.0fMB/s", name, filepath.Base(out), mb, ms, mb/(ms/1000))
				if *delSrc {
					_ = os.Remove(ncm)
				}
				okN.Add(1)
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()

	log.printf("=== 解密完成 ok=%d skip=%d err=%d 耗时=%.2fs ===", okN.Load(), skipN.Load(), erN.Load(), time.Since(start).Seconds())

	// 去重比较
	log.printf("=== 重复文件比较 (apply=%v) ===", *dedupApply)
	dedupPass(*dir, log, *dedupApply)
	log.printf("=== 全部完成 ===")
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
