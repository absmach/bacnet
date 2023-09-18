package encoding

import (
	"bytes"
	"encoding/binary"
	"math"
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

func EncodeContextUnsigned(tagNum BACnetApplicationTag, val uint32) []byte {
	len := 0
	switch {
	case val < 0x100:
		len = 1
	case val < 0x10000:
		len = 2
	case val < 0x1000000:
		len = 3
	default:
		len = 4
	}
	return append(EncodeTag(tagNum, true, len), EncodeUnsigned(val)...)
}

// EncodeApplicationUnsigned encodes an unsigned integer value as a BACnet application tag.
func EncodeApplicationUnsigned(value uint32) []byte {
	tmp := EncodeUnsigned(value)
	tag := EncodeTag(UnsignedInt, false, len(tmp))
	return append(tag, tmp...)
}

func EncodeApplicationEnumerated(value uint32) []byte {
	tmp := EncodeUnsigned(value)
	return append(EncodeTag(Enumerated, false, len(tmp)), tmp...)
}

func EncodeApplicationOctetString(octetString []byte, octetOffset, octetCount int) []byte {
	tag := EncodeTag(OctetString, false, octetCount)
	octetStringSegment := octetString[octetOffset : octetOffset+octetCount]
	return append(tag, octetStringSegment...)
}

func EncodeApplicationCharacterString(value string) []byte {
	tmp := encodeBACnetCharacterString(value)
	tag := EncodeTag(CharacterString, false, len(tmp))
	return append(tag, tmp...)
}

func encodeBACnetCharacterString(value string) []byte {
	encoding := []byte{byte(CharacterUTF8)}
	encodedValue := []byte(value)
	return append(encoding, encodedValue...)
}

func EncodeApplicationBoolean(val bool) []byte {
	if val {
		return EncodeTag(Boolean, false, 1)
	}
	return EncodeTag(Boolean, false, 0)
}

func EncodeApplicationSigned(val int32) []byte {
	tmp := EncodeSigned(val)
	return append(EncodeTag(SignedInt, false, len(tmp)), tmp...)
}

func EncodeApplicationReal(val float32) []byte {
	return append(EncodeTag(Real, false, 4), encodeBACnetReal(val)...)
}

func EncodeApplicationDouble(val float64) []byte {
	return append(EncodeTag(Double, false, 8), encodeBACnetDouble(val)...)
}

func encodeBACnetReal(value float32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, math.Float32bits(value))
	return buf
}

func encodeBACnetDouble(value float64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, math.Float64bits(value))
	return buf
}

func EncodeApplicationBitString(val interface{}) []byte {
	// TODO
	return nil
}

func EncodeContextObjectId(tagNumber BACnetApplicationTag, objectType ObjectType, instance uint32) []byte {
	tag := EncodeTag(tagNumber, true, 4)
	objectId := encodeBacnetObjectId(objectType, instance)
	return append(tag, objectId...)
}

func encodeBacnetObjectId(objectType ObjectType, instance uint32) []byte {
	objectId := ((uint32(objectType) & MaxObject) << InstanceBits) | (instance & MaxInstance)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, objectId)
	return buf
}

func EncodeClosingOpeningTag(tagNum BACnetApplicationTag, opening bool) []byte {
	tag := make([]byte, 2)
	tag[0] = 0x8
	if tagNum <= 14 {
		tag[0] |= (byte(tagNum) << 4)
	} else {
		tag[0] |= 0xF0
		binary.BigEndian.PutUint16(tag[1:], uint16(tagNum))
	}
	if opening {
		// Set the type field to opening tag.
		tag[0] |= 6
		return tag
	}
	// Set the type field to closing tag.
	tag[0] |= 7

	return tag
}
