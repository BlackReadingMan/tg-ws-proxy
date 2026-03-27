package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

type MsgSplitter struct {
	dec       cipher.Stream
	proto     uint32
	cipherBuf []byte
	plainBuf  []byte
	disabled  bool
}

func NewMsgSplitter(initData []byte, proto uint32) (*MsgSplitter, error) {
	if len(initData) < 56 {
		return nil, fmt.Errorf("init data too short")
	}
	key := initData[8:40]
	iv := initData[40:56]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dec := cipher.NewCTR(block, iv)

	dummy := make([]byte, 64)
	dec.XORKeyStream(dummy, dummy)

	return &MsgSplitter{
		dec:       dec,
		proto:     proto,
		cipherBuf: make([]byte, 0),
		plainBuf:  make([]byte, 0),
		disabled:  false,
	}, nil
}

func (s *MsgSplitter) Split(chunk []byte) [][]byte {
	if len(chunk) == 0 {
		return nil
	}
	if s.disabled {
		return [][]byte{chunk}
	}

	s.cipherBuf = append(s.cipherBuf, chunk...)

	plainPart := make([]byte, len(chunk))
	s.dec.XORKeyStream(plainPart, chunk)
	s.plainBuf = append(s.plainBuf, plainPart...)

	var parts [][]byte
	for len(s.cipherBuf) > 0 {
		pktLen := s.nextPacketLen()
		if pktLen == 0 {
			parts = append(parts, s.cipherBuf)
			s.cipherBuf = nil
			s.plainBuf = nil
			s.disabled = true
			break
		}
		if pktLen < 0 {
			break
		}
		parts = append(parts, s.cipherBuf[:pktLen])
		s.cipherBuf = s.cipherBuf[pktLen:]
		s.plainBuf = s.plainBuf[pktLen:]
	}
	return parts
}

func (s *MsgSplitter) Flush() [][]byte {
	if len(s.cipherBuf) == 0 {
		return nil
	}
	tail := make([]byte, len(s.cipherBuf))
	copy(tail, s.cipherBuf)
	s.cipherBuf = nil
	s.plainBuf = nil
	return [][]byte{tail}
}

func (s *MsgSplitter) nextPacketLen() int {
	if len(s.plainBuf) == 0 {
		return -1
	}
	switch s.proto {
	case PROTO_ABRIDGED:
		return s.nextAbridgedLen()
	case PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE:
		return s.nextIntermediateLen()
	default:
		return 0
	}
}

func (s *MsgSplitter) nextAbridgedLen() int {
	first := s.plainBuf[0]
	if first == 0x7F || first == 0xFF {
		if len(s.plainBuf) < 4 {
			return -1
		}
		payloadLen := int(binary.LittleEndian.Uint32(s.plainBuf[1:5])&0xFFFFFF) * 4
		headerLen := 4
		if payloadLen <= 0 {
			return 0
		}
		pktLen := headerLen + payloadLen
		if len(s.plainBuf) < pktLen {
			return -1
		}
		return pktLen
	}
	payloadLen := int(first&0x7F) * 4
	if payloadLen <= 0 {
		return 0
	}
	pktLen := 1 + payloadLen
	if len(s.plainBuf) < pktLen {
		return -1
	}
	return pktLen
}

func (s *MsgSplitter) nextIntermediateLen() int {
	if len(s.plainBuf) < 4 {
		return -1
	}
	payloadLen := int(binary.LittleEndian.Uint32(s.plainBuf[:4]) & 0x7FFFFFFF)
	if payloadLen <= 0 {
		return 0
	}
	pktLen := 4 + payloadLen
	if len(s.plainBuf) < pktLen {
		return -1
	}
	return pktLen
}
