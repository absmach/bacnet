package bacnet

import "github.com/absmach/bacnet/encoding"

type WhoIs struct {
	HighLimit, LowLimit *uint32
}

func (w *WhoIs) Decode(buf []byte, offset, apduLen int) int {
	if apduLen <= 0 {
		return 0
	}
	length, tagNum, lenVal := encoding.DecodeTagNumberAndValue(buf, offset)
	if tagNum != 0 {
		return -1
	}
	if apduLen > length {
		len1, decVal := encoding.DecodeUnsigned(buf, offset+length, int(lenVal))
		length += len1

		if decVal <= encoding.MaxInstance {
			w.LowLimit = &decVal
		}

		if apduLen > length {
			len1, tagNum, lenVal := encoding.DecodeTagNumberAndValue(buf, offset+length)
			length += len1
			if tagNum != 1 {
				return -1
			}
			if apduLen > length {
				len1, _ := encoding.DecodeUnsigned(buf, offset+length, int(lenVal))
				length += len1
				if decVal <= encoding.MaxInstance {
					w.HighLimit = &decVal
				}
			} else {
				return -1
			}
		} else {
			return -1
		}
	} else {
		return -1
	}
	return length
}

func (w WhoIs) Encode() []byte {
	if w.LowLimit != nil && *w.LowLimit <= encoding.MaxInstance &&
		w.HighLimit != nil && *w.HighLimit <= encoding.MaxInstance {
		return append(encoding.EncodeContextUnsigned(0, *w.LowLimit), encoding.EncodeContextUnsigned(1, *w.HighLimit)...)
	}
	return []byte{}
}
