package encoding

import (
	"encoding/binary"
	"math"
	"time"
)

type BacnetCharacterStringEncodings int

const (
	CharacterANSIX34  BacnetCharacterStringEncodings = 0
	CharacterUTF8     BacnetCharacterStringEncodings = 0
	CharacterMSDBCS   BacnetCharacterStringEncodings = 1
	CharacterJISC6226 BacnetCharacterStringEncodings = 2
	CharacterJISX0208 BacnetCharacterStringEncodings = 2
	CharacterUCS4     BacnetCharacterStringEncodings = 3
	CharacterUCS2     BacnetCharacterStringEncodings = 4
	CharacterISO8859  BacnetCharacterStringEncodings = 5
)

func DecodeUnsigned(buffer []byte, offset, len int) (int, uint32) {
	value := uint32(0)
	for i := 0; i < len; i++ {
		value += uint32(buffer[offset+i]) << uint(8*(len-i-1))
	}
	return len, value
}

func DecodeOctetString(buf []byte, offset, lenVal int) (int, []byte) {
	tmp := make([]byte, lenVal)
	copy(tmp, buf[offset:offset+lenVal])
	return len(tmp), tmp
}

// multiCharsetCharacterstringDecode decodes a multi-character set character string.
func multiCharsetCharacterStringDecode(buffer []byte, offset, maxLength int, encoding BacnetCharacterStringEncodings, length int) (bool, string) {
	var charString, enc string

	switch encoding {
	case CharacterUCS2:
		enc = "utf-16"
	case CharacterUCS4:
		enc = "utf-32"
	case CharacterISO8859:
		enc = "latin-1"
	case CharacterJISX0208:
		enc = "shift_jisx0213"
	case CharacterMSDBCS:
		enc = "dbcs"
	default:
		enc = "utf-8"
	}

	c := make([]byte, 0)
	for i := 0; i < length; i++ {
		c = append(c, buffer[offset+i])
	}

	if enc == "utf-8" {
		charString = string(c)
	} else {
		charString = string(c)
		charString = string([]rune(charString)) // Convert to Unicode
	}

	return true, charString
}

func DecodeCharacterString(buffer []byte, offset, maxLength, lenValue int) (int, string) {
	leng := 0
	status := false
	var charString string

	status, charString = multiCharsetCharacterStringDecode(buffer, offset+1, maxLength, BacnetCharacterStringEncodings(buffer[offset]), lenValue-1)
	if status {
		leng = lenValue
	}

	return leng, charString
}

func decodeContextCharacterString(buffer []byte, offset, maxLength int, tagNumber byte) (int, string) {
	leng := 0
	status := false
	charString := ""

	if IsContextTag(buffer, offset+leng, tagNumber) {
		leng1, _, lenValue := DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1

		status, charString = multiCharsetCharacterStringDecode(buffer, offset+1+leng, maxLength, BacnetCharacterStringEncodings(buffer[offset+leng]), int(lenValue)-1)
		if status {
			leng += int(lenValue)
		} else {
			leng = -1
		}
	}

	return leng, charString
}

func DecodeSigned(buffer []byte, offset int, lenValue int) (int, int) {
	value := 0
	for i := 0; i < lenValue; i++ {
		value += int(buffer[offset+i]) << uint(8*(lenValue-i-1))
	}
	// Check if it is negative
	if value > int(math.Pow(256, float64(lenValue))/2)-1 {
		value = -(int(math.Pow(256, float64(lenValue))) - value)
	}
	return lenValue, value
}

func decodeReal(buffer []byte, offset int) (int, float32) {
	value := binary.BigEndian.Uint32(buffer[offset : offset+4])
	return 4, math.Float32frombits(value)
}

func DecodeRealSafe(buffer []byte, offset int, lenValue int) (int, float32) {
	if lenValue != 4 {
		value := float32(0.0)
		return lenValue, value
	}
	return decodeReal(buffer, offset)
}

func decodeDouble(buffer []byte, offset int) (int, float64) {
	value := binary.BigEndian.Uint64(buffer[offset : offset+8])
	return 8, math.Float64frombits(value)
}

func DecodeDoubleSafe(buffer []byte, offset int, lenValue int) (int, float64) {
	if lenValue != 8 {
		value := float64(0.0)
		return lenValue, value
	}
	return decodeDouble(buffer, offset)
}

func DecodeBACnetTimeSafe(buf []byte, offset, lenVal int) (int, time.Time) {
	if lenVal != 4 {
		return lenVal, time.Time{}
	}
	return decodeBACnetTime(buf, offset)
}
