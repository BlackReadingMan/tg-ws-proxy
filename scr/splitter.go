package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

type MsgSplitter struct {
	stream cipher.Stream
}

func NewMsgSplitter(initData []byte) (*MsgSplitter, error) {
	if len(initData) < 56 {
		return nil, fmt.Errorf("init data too short")
	}
	key := initData[8:40]
	iv := initData[40:56]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	// skip first 64 bytes of keystream (as in Python: decryptor.update(b'\x00'*64))
	dummy := make([]byte, 64)
	stream.XORKeyStream(dummy, dummy)
	return &MsgSplitter{stream: stream}, nil
}

func (s *MsgSplitter) Split(chunk []byte) [][]byte {
	// decrypt a copy to find boundaries
	plain := make([]byte, len(chunk))
	copy(plain, chunk)
	s.stream.XORKeyStream(plain, plain)

	boundaries := []int{}
	pos := 0
	for pos < len(plain) {
		first := plain[pos]
		if first == 0x7f {
			if pos+4 > len(plain) {
				break
			}
			msgLen := int(binary.LittleEndian.Uint32(plain[pos+1:pos+5])&0xFFFFFF) * 4
			pos += 4
			if msgLen == 0 || pos+msgLen > len(plain) {
				break
			}
			pos += msgLen
			boundaries = append(boundaries, pos)
		} else {
			msgLen := int(first) * 4
			pos += 1
			if msgLen == 0 || pos+msgLen > len(plain) {
				break
			}
			pos += msgLen
			boundaries = append(boundaries, pos)
		}
	}
	if len(boundaries) <= 1 {
		return [][]byte{chunk}
	}
	parts := make([][]byte, 0, len(boundaries))
	prev := 0
	for _, b := range boundaries {
		parts = append(parts, chunk[prev:b])
		prev = b
	}
	if prev < len(chunk) {
		parts = append(parts, chunk[prev:])
	}
	return parts
}
