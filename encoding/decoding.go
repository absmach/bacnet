package encoding

func DecodeUnsigned(buffer []byte, offset, len int) (int, uint32) {
	value := uint32(0)
	for i := 0; i < len; i++ {
		value += uint32(buffer[offset+i]) << uint(8*(len-i-1))
	}
	return len, value
}
