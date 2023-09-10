package bacnet

import (
	"github.com/absmach/bacnet/pkg/encoding"
)

type PropertyValue struct {
	Identifier encoding.PropertyIdentifier
	Arrayindex *uint32
	Value      uint32
	Priority   uint32
}

type ReadPropertyRequest struct {
	ObjectIdentifier   *ObjectIdentifier
	PropertyIdentifier interface{}
	PropertyArrayIndex uint32
}

func (r ReadPropertyRequest) Encode() []byte {
	var ret []byte

	if r.ObjectIdentifier != nil {
		ret = append(ret, r.ObjectIdentifier.EncodeContext(0)...)
	}

	propID := r.PropertyIdentifier.(encoding.PropertyIdentifier)

	ret = append(ret, encoding.EncodeContextEnumerated(1, uint32(propID))...)

	if r.PropertyArrayIndex != 0 {
		ret = append(ret, encoding.EncodeContextUnsigned(2, r.PropertyArrayIndex)...)
	}

	return ret
}

func (r *ReadPropertyRequest) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0

	// objectIdentifier
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		r.ObjectIdentifier = &ObjectIdentifier{}
		leng += r.ObjectIdentifier.Decode(buffer, offset+leng, int(lenValue))
	} else {
		return -1
	}

	// propertyIdentifier
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, r.PropertyIdentifier = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		leng += leng1
	} else {
		return -1
	}

	// propertyArrayIndex (optional)
	if leng < apduLen && encoding.IsContextTag(buffer, offset+leng, 2) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, r.PropertyArrayIndex = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))

		leng += leng1
	}

	return leng
}
