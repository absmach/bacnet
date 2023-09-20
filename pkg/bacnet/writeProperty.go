package bacnet

import (
	"errors"

	"github.com/absmach/bacnet/pkg/encoding"
)

type WritePropertyRequest struct {
	ObjectIdentifier   ObjectIdentifier
	PropertyIdentifier interface{}
	PropertyArrayIndex uint32
	PropertyValue      []BACnetValue
	Priority           uint32
}

func (wpr *WritePropertyRequest) Decode(buffer []byte, offset, apduLen int) (int, error) {
	var leng int

	// objectidentifier
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		wpr.ObjectIdentifier = ObjectIdentifier{}
		leng1 = wpr.ObjectIdentifier.Decode(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1, errors.New("Decoding objectidentifier failed")
	}

	// propertyidentifier
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, wpr.PropertyIdentifier = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		leng += leng1
	} else {
		return -1, errors.New("Decoding propertyidentifier failed")
	}

	// propertyarrayindex optional
	if leng < apduLen {
		if encoding.IsContextTag(buffer, offset+leng, 2) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, wpr.PropertyArrayIndex = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	// property-value
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 3) {
		leng++
		wpr.PropertyValue = make([]BACnetValue, 0)
		for !encoding.IsClosingTagNumber(buffer, offset+leng, 3) && leng < apduLen {
			bValue := BACnetValue{}
			propId := wpr.PropertyIdentifier.(encoding.PropertyIdentifier)
			leng1, err := bValue.Decode(buffer, offset+leng, apduLen-leng, &wpr.ObjectIdentifier.Type, &propId)
			if err != nil {
				return -1, err
			}
			leng += leng1
			wpr.PropertyValue = append(wpr.PropertyValue, bValue)
		}
		if encoding.IsClosingTagNumber(buffer, offset+leng, 3) {
			leng++
		} else {
			return -1, errors.New("decoding error for property_value")
		}
	} else {
		return -1, errors.New("decoding error for property_value")
	}

	if leng < apduLen {
		// priority
		if encoding.IsContextTag(buffer, offset+leng, 4) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, wpr.Priority = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	return leng, nil
}

func (wpr *WritePropertyRequest) Encode() []byte {
	buf := encoding.EncodeContextObjectId(0, wpr.ObjectIdentifier.Type, uint32(wpr.ObjectIdentifier.Instance))
	propId := wpr.PropertyIdentifier.(encoding.PropertyIdentifier)
	buf = append(buf, encoding.EncodeContextEnumerated(1, uint32(propId))...)

	// Optional array index; ALL is -1 which is assumed when missing
	if wpr.PropertyArrayIndex != encoding.ArrayAll {
		buf = append(buf, encoding.EncodeContextUnsigned(2, wpr.PropertyArrayIndex)...)
	}

	// PropertyValue
	buf = append(buf, encoding.EncodeClosingOpeningTag(3, true)...)
	for _, value := range wpr.PropertyValue {
		buf = append(buf, value.Encode()...)
	}
	buf = append(buf, encoding.EncodeClosingOpeningTag(3, false)...)

	// Optional priority - 0 if not set, 1..16 if set
	if wpr.Priority != encoding.NoPriority {
		buf = append(buf, encoding.EncodeContextUnsigned(4, wpr.Priority)...)
	}

	return buf
}
