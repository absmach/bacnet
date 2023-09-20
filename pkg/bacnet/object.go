package bacnet

import (
	"encoding/binary"

	"github.com/absmach/bacnet/pkg/encoding"
)

type ObjectInstance uint32

type ObjectIdentifier struct {
	Type     encoding.ObjectType
	Instance ObjectInstance
}

func (oi *ObjectIdentifier) Decode(buf []byte, offset, apdulen int) int {
	len, val := encoding.DecodeUnsigned(buf, offset, 4)
	oi.Instance = ObjectInstance(val) & ObjectInstance(encoding.MaxInstance)
	oi.Type = encoding.ObjectType(val >> encoding.InstanceBits & encoding.MaxObject)
	return len
}

func (oi *ObjectIdentifier) DecodeContext(buf []byte, offset, apdulen int, tagNumber byte) int {
	len := 0
	if encoding.IsContextTag(buf, offset+len, tagNumber) {
		len1, _, lenVal := encoding.DecodeTagNumberAndValue(buf, offset+len)
		len += len1
		len += oi.Decode(buf, offset+len1, int(lenVal))
		return len
	}
	return -1
}

func (oi ObjectIdentifier) Encode() []byte {
	value := uint32(oi.Type)&encoding.MaxObject<<encoding.InstanceBits | (uint32(oi.Instance) & encoding.MaxInstance)
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}

func (oi ObjectIdentifier) EncodeApp() []byte {
	tmp := oi.Encode()
	return append(encoding.EncodeTag(encoding.BACnetObjectIdentifier, false, len(tmp)), tmp...)
}

func (oi ObjectIdentifier) EncodeContext(tagNum int) []byte {
	tmp := oi.Encode()
	return append(encoding.EncodeTag(encoding.BACnetApplicationTag(tagNum), true, len(tmp)), tmp...)
}
