package internal

import "errors"

var errBitArrayLen = errors.New("bit array length must be 8 to convert to byte")

type BitArray struct {
	bits []bool
}

func NewBitArray(length int) *BitArray {
	return &BitArray{
		bits: make([]bool, length),
	}
}

func (ba *BitArray) Set(index int, value bool) {
	if index >= 0 && index < len(ba.bits) {
		ba.bits[index] = value
	}
}

func (ba *BitArray) Get(index int) bool {
	if index >= 0 && index < len(ba.bits) {
		return ba.bits[index]
	}
	return false
}

func (ba *BitArray) ToByte() (byte, error) {
	// Ensure the length of the bit array is 8 to convert to a byte.
	if len(ba.bits) != 8 {
		return 0, errBitArrayLen
	}

	var byteValue byte
	for j := 0; j < 8; j++ {
		if ba.bits[j] {
			byteValue |= 1 << uint(7-j)
		}
	}

	return byteValue, nil
}

func NewBitArrayFromByte(byteValue byte) *BitArray {
	bitArray := NewBitArray(8)
	for j := 0; j < 8; j++ {
		bitArray.Set(j, byteValue&(1<<uint(7-j)) != 0)
	}
	return bitArray
}
