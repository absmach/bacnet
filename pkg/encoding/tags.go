package encoding

type BACnetApplicationTag int

const (
	Null BACnetApplicationTag = iota
	Boolean
	UnsignedInt
	SignedInt
	Real
	Double
	OctetString
	CharacterString
	BitString
	Enumerated
	Date
	Time
	BACnetObjectIdentifier
	Reserve1
	Reserve2
	Reserve3
)

func isExtendedTagNumber(b byte) bool {
	return (b & 0xF0) == 0xF0
}

func isExtendedValue(b byte) bool {
	return (b & 0x07) == 5
}

func isOpeningTag(b byte) bool {
	return (b & 0x07) == 6
}

func isClosingTag(b byte) bool {
	return (b & 0x07) == 7
}

func IsContextSpecific(b byte) bool {
	return (b & 0x8) == 0x8
}

func IsContextTag(buf []byte, offset int, tagNum byte) bool {
	_, myTagNum := decodeTagNumber(buf, offset)
	return IsContextSpecific(buf[offset]) && myTagNum == tagNum

}

func IsContextTagWithLength(buf []byte, offset int, tagNum byte) (int, bool) {
	tagLen, myTagNum := decodeTagNumber(buf, offset)
	return tagLen, IsContextSpecific(buf[offset]) && myTagNum == tagNum
}

func DecodeTagNumberAndValue(buf []byte, offset int) (len int, tagNum byte, val uint32) {
	len, tagNum = decodeTagNumber(buf, offset)

	switch {
	case isExtendedValue(buf[offset]):
		switch buf[offset+len] {
		case 255:
			len += 1
			len1, val1 := DecodeUnsigned(buf, offset+len, 4)
			len += len1
			val = val1
		case 254:
			len += 1
			len1, val1 := DecodeUnsigned(buf, offset+len, 2)
			len += len1
			val = val1
		default:
			val = uint32(buf[offset+len])
			len += 1
		}
	case isOpeningTag(buf[offset]), isClosingTag(buf[offset]):
		val = 0
	default:
		val = uint32(buf[offset] & 0x07)
	}
	return len, tagNum, val

}

func decodeTagNumber(buf []byte, offset int) (len int, tagNum byte) {
	len = 1

	if isExtendedTagNumber(buf[offset]) {
		return len + 1, buf[offset+len]
	}
	return len, buf[offset] >> 4
}

func EncodeTag(tagNum BACnetApplicationTag, ctxSpecific bool, lenVal int) []byte {
	tag := []byte{}
	value := byte(0)

	if ctxSpecific {
		value = 0x8
	}

	if tagNum <= 14 {
		value += byte(tagNum) << 4
		tag = append(tag, value)
	} else {
		value += 0xF0
		tag = append(tag, value)
		tag = append(tag, byte(tagNum))
	}

	if lenVal <= 4 {
		tag[0] += byte(lenVal)
		return tag
	}
	tag[0] += 5
	switch {
	case lenVal <= 253:
		tag = append(tag, byte(lenVal))
		return tag
	case lenVal <= 65535:
		tag = append(tag, 254)
		return append(tag, EncodeUnsigned(uint32(lenVal))...)
	default:
		tag = append(tag, 255)
		return append(tag, EncodeUnsigned(uint32(lenVal))...)
	}
}

func IsOpeningTagNumber(buf []byte, offset int, tagNum byte) bool {
	_, myTagNum := decodeTagNumber(buf, offset)
	return isOpeningTag(buf[offset]) && myTagNum == tagNum
}

func IsClosingTagNumber(buf []byte, offset int, tagNum byte) bool {
	_, myTagNum := decodeTagNumber(buf, offset)
	return isClosingTag(buf[offset]) && myTagNum == tagNum
}
