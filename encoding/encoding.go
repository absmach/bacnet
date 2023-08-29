package encoding

import (
	"bytes"
	"encoding/binary"
)

const (
	MaxObject         = 0x3FF
	InstanceBits      = 22
	MaxInstance       = 0x3FFFFF
	MaxBitstringBytes = 15
	ArrayAll          = 0xFFFFFFFF
	NoPriority        = 0
	MinPriority       = 1
	MaxPriority       = 16
)

func EncodeUnsigned(value uint32) []byte {
	switch {
	case value < 0x100:
		buf := make([]byte, 1)
		buf[0] = uint8(value)
		return buf
	case value < 0x10000:
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(value))
		return buf
	case value < 0x1000000:
		buf := make([]byte, 3)
		buf[0] = byte((value & 0xff0000) >> 16)
		buf[1] = byte((value & 0x00ff00) >> 8)
		buf[2] = byte(value & 0x0000ff)
		return buf
	default:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, value)
		return buf
	}
}

func EncodeSigned(value int32) []byte {
	switch {
	case value < 0x100:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint8(value))
		return buf.Bytes()
	case value < 0x10000:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint16(value))
		return buf.Bytes()
	case value < 0x1000000:
		buf := make([]byte, 3)
		buf[0] = byte((value & 0xff0000) >> 16)
		buf[1] = byte((value & 0x00ff00) >> 8)
		buf[2] = byte(value & 0x0000ff)
		return buf
	default:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, value)
		return buf.Bytes()
	}
}
