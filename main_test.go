package main

import (
	"bytes"
	"math/rand"
	"testing"
)

// naiveDecrypt 是 decryptChunk 的逐字节参考实现,用于对拍向量化版本。
func naiveDecrypt(buf []byte, pad *[256]byte) {
	for i := range buf {
		buf[i] ^= pad[i&0xff]
	}
}

func randPad() [256]byte {
	var p [256]byte
	rand.Read(p[:])
	return p
}

// TestDecryptChunkMatchesNaive:uint64 宽字路径必须与逐字节实现逐位一致,
// 覆盖各种长度(含非 8 字节对齐的尾部)。
func TestDecryptChunkMatchesNaive(t *testing.T) {
	pad := randPad()
	for _, n := range []int{0, 1, 7, 8, 9, 255, 256, 257, 1000, chunkSize, chunkSize + 3} {
		src := make([]byte, n)
		rand.Read(src)

		got := append([]byte(nil), src...)
		decryptChunk(got, &pad)

		want := append([]byte(nil), src...)
		naiveDecrypt(want, &pad)

		if !bytes.Equal(got, want) {
			t.Fatalf("长度 %d:向量化结果与朴素实现不一致", n)
		}
	}
}

// TestDecryptChunkInvolution:XOR keystream 是自反操作,两次还原原文。
func TestDecryptChunkInvolution(t *testing.T) {
	pad := randPad()
	orig := make([]byte, 5000)
	rand.Read(orig)

	buf := append([]byte(nil), orig...)
	decryptChunk(buf, &pad)
	if bytes.Equal(buf, orig) {
		t.Fatal("一次解密后不应等于原文")
	}
	decryptChunk(buf, &pad)
	if !bytes.Equal(buf, orig) {
		t.Fatal("两次解密应还原原文")
	}
}

func TestPkcs7unpad(t *testing.T) {
	// 合法:3 字节填充
	if out, err := pkcs7unpad([]byte{1, 2, 3, 3, 3, 3}); err != nil || !bytes.Equal(out, []byte{1, 2, 3}) {
		t.Fatalf("合法填充解析错误: out=%v err=%v", out, err)
	}
	// 非法:空 / 填充长度越界 / 填充为 0
	for _, bad := range [][]byte{{}, {5, 5}, {1, 2, 0}} {
		if _, err := pkcs7unpad(bad); err == nil {
			t.Fatalf("应拒绝非法填充: %v", bad)
		}
	}
}

// TestBuildPad:keystream 周期为 256,buildPad 应产出 256 字节且与 key_box 推导一致。
func TestBuildPad(t *testing.T) {
	var box [256]byte
	rand.Read(box[:])
	pad := buildPad(box)
	for p := 0; p < 256; p++ {
		j := (p + 1) & 0xff
		want := box[(int(box[j])+int(box[(int(box[j])+j)&0xff]))&0xff]
		if pad[p] != want {
			t.Fatalf("pad[%d]=%d, want %d", p, pad[p], want)
		}
	}
}
