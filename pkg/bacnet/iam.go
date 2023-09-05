package bacnet

/*
import (
	"errors"

	"github.com/absmach/bacnet/encoding"
)

type IAmRequest struct {
	IamDeviceIdentifier   ObjectIdentifier
	MaxAPDULengthAccepted uint32
	SegmentationSupported int
	VendorID              uint32
}

func (iam *IAmRequest) ASN1Decode(buffer []byte, offset int, apduLen int) (int, error) {
	leng := 0
	iam.IamDeviceIdentifier = ObjectIdentifier{}
	// OBJECT ID - object id
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1

	if tagNumber != byte(BACnetObjectIdentifier) {
		return -1, errors.New("Invalid tag number")
	}

	leng = iam.IamDeviceIdentifier.Decode(buffer, offset+leng, int(lenValue))

	if iam.IamDeviceIdentifier.Type != ObjectTypeDevice {
		// Handle error or log message
		return -1, errors.New("Got Iam from no device")
	}

	// MAX APDU - unsigned
	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber != byte(UnsignedInt) {
		return -1, errors.New("Invalid tag number")
	}

	leng1, decodedValue := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
	leng += leng1
	iam.MaxAPDULengthAccepted = decodedValue

	// Segmentation - enumerated
	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber != byte(Enumerated) {
		return -1, errors.New("Invalid tag number")
	}
	segmentationSupported, err := encoding.DecodeEnumerated(buffer, offset+leng, lenValue, SegmentationSupported)
	if err != nil {
		return -1, err
	}
	leng += leng1
	iam.SegmentationSupported = segmentationSupported

	// Vendor ID - unsigned16
	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1

	if tagNumber != byte(UnsignedInt) {
		return -1, errors.New("Invalid tag number")
	}

	leng1, decodedValue = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
	if err != nil {
		return -1, err
	}

	leng += leng1
	if decodedValue > 0xFFFF {
		return -1, errors.New("Value exceeds 0xFFFF")
	}
	iam.VendorID = decodedValue

	return leng, nil
}

func (iam *IAmRequest) ASN1Encode() []byte {
	tmp := iam.IamDeviceIdentifier.Encode()
	return append(append(append(append([]byte{}, encoding.EncodeTag(encoding.BACnetApplicationTag(BACnetObjectIdentifier), false, len(tmp))...), tmp...), encoding.EncodeApplicationUnsigned(iam.MaxAPDULengthAccepted)...), encoding.EncodeApplicationEnumerated(iam.SegmentationSupported, SegmentationSupported), encoding.EncodeApplicationUnsigned(iam.VendorID)...)
}

type YouAreRequest struct {
	VendorID         uint32
	ModelName        string
	SerialNumber     string
	DeviceIdentifier ObjectIdentifier
	DeviceMACAddress []byte
}

func (youAre *YouAreRequest) ASN1Decode(buffer []byte, offset int, apduLen int) (int, error) {
	leng := 0

	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber == byte(UnsignedInt) {
		leng1, decodedValue := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
		youAre.VendorID = decodedValue
	} else {
		return -1, errors.New("Invalid tag number")
	}

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber == byte(CharacterString) {
		decodedValue, err := encoding.DecodeCharacterString(buffer, offset+leng, apduLen-leng, lenValue)
		if err != nil {
			return -1, err
		}
		leng += decodedValue
		youAre.ModelName = decodedValue
	} else {
		return -1, errors.New("Invalid tag number")
	}

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber == byte(CharacterString) {
		decodedValue, err := encoding.DecodeCharacterString(buffer, offset+leng, apduLen-leng, lenValue)
		if err != nil {
			return -1, err
		}
		leng += decodedValue
		youAre.SerialNumber = decodedValue
	} else {
		return -1, errors.New("Invalid tag number")
	}

	if leng < apduLen {
		leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		if tagNumber == byte(BACnetObjectIdentifier) {
			leng += leng1
			youAre.DeviceIdentifier = ObjectIdentifier{}
			leng = youAre.DeviceIdentifier.Decode(buffer, offset+leng, int(lenValue))
		}
	}

	if leng < apduLen {
		leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		if tagNumber == byte(OctetString) {
			leng += leng1
			leng1, decodedValue := encoding.DecodeOctetString(buffer, offset+leng, int(lenValue))
			leng += leng1
			youAre.DeviceMACAddress = decodedValue
		}
	}

	return leng, nil
}

func (youAre *YouAreRequest) ASN1Encode() []byte {
	buffer := append(append(append([]byte{}, encoding.EncodeApplicationUnsigned(youAre.VendorID)...),
		encoding.EncodeApplicationCharacterString(youAre.ModelName)...),
		encoding.EncodeApplicationCharacterString(youAre.SerialNumber)...)

	if youAre.DeviceIdentifier != (ObjectIdentifier{}) {
		buffer = append(buffer, youAre.DeviceIdentifier.EncodeApp()...)
	}

	if len(youAre.DeviceMACAddress) > 0 {
		buffer = append(buffer, encoding.EncodeApplicationOctetString(youAre.DeviceMACAddress, 0, len(youAre.DeviceMACAddress))...)
	}

	return buffer
}
*/
