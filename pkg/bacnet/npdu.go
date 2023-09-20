package bacnet

import (
	"encoding/binary"
	"errors"

	"github.com/absmach/bacnet/internal"
)

var errNPDUVersion = errors.New("unexpected NPDU version")

type NPDU struct {
	Version     uint8 // Always one.
	Control     NPDUControlInformation
	DNET        uint16
	DLEN        uint8
	DADR        []byte
	Destination *BACnetAddress
	SNET        uint16
	SLEN        uint8
	SADR        []byte
	Source      *BACnetAddress
	MessageType byte
	HopCount    byte
	VendorID    uint16
}

type NPDUControlInformation struct {
	control internal.BitArray
}

func NewNPDUControlInformation() *NPDUControlInformation {
	return &NPDUControlInformation{
		control: *internal.NewBitArray(8),
	}
}

func (nci *NPDUControlInformation) IsNetworkLayerMessage() bool {
	return nci.control.Get(0)
}

func (nci *NPDUControlInformation) SetNetworkLayerMessage(a bool) {
	nci.control.Set(0, a)
}

func (nci *NPDUControlInformation) IsDestinationSpecifier() bool {
	return nci.control.Get(2)
}

func (nci *NPDUControlInformation) SetDestinationSpecifier(a bool) {
	nci.control.Set(2, a)
}

func (nci *NPDUControlInformation) IsSourceSpecifier() bool {
	return nci.control.Get(4)
}

func (nci *NPDUControlInformation) SetSourceSpecifier(a bool) {
	nci.control.Set(4, a)
}

func (nci *NPDUControlInformation) IsDataExpectingReply() bool {
	return nci.control.Get(5)
}

func (nci *NPDUControlInformation) SetDataExpectingReply(a bool) {
	nci.control.Set(5, a)
}

func (nci *NPDUControlInformation) NetworkPriority() (NetworkPriority, error) {
	if !nci.control.Get(6) && !nci.control.Get(7) {
		return NormalMessage, nil
	} else if !nci.control.Get(6) && nci.control.Get(7) {
		return UrgentMessage, nil
	} else if nci.control.Get(6) && !nci.control.Get(7) {
		return CriticalEquipmentMessage, nil
	} else if nci.control.Get(6) && nci.control.Get(7) {
		return LifeSafetyMessage, nil
	}
	return 0, errors.New("invalid network priority")
}

func (nci *NPDUControlInformation) SetNetworkPriority(a NetworkPriority) error {
	switch a {
	case NormalMessage:
		nci.control.Set(6, false)
		nci.control.Set(7, false)
	case UrgentMessage:
		nci.control.Set(6, false)
		nci.control.Set(7, true)
	case CriticalEquipmentMessage:
		nci.control.Set(6, true)
		nci.control.Set(7, false)
	case LifeSafetyMessage:
		nci.control.Set(6, true)
		nci.control.Set(7, true)
	default:
		return errors.New("invalid network priority")
	}
	return nil
}

func (nci *NPDUControlInformation) Encode() ([]byte, error) {
	b, err := nci.control.ToByte()
	if err != nil {
		return []byte{}, err
	}
	return []byte{b}, nil
}

func (nci *NPDUControlInformation) Decode(buffer []byte, offset int) int {
	if offset < len(buffer) {
		nci.control = *internal.NewBitArrayFromByte(buffer[offset])
		return 1
	}
	return 0
}

func NewNPDU(destination *BACnetAddress, source *BACnetAddress, hopCount *uint8, vendorID *uint16) *NPDU {
	npdu := &NPDU{
		Version:     1,
		Control:     *NewNPDUControlInformation(),
		Destination: destination,
		Source:      source,
	}
	switch hopCount {
	case nil:
		npdu.HopCount = 255
	default:
		npdu.HopCount = *hopCount
	}
	if vendorID != nil {
		npdu.VendorID = *vendorID
	}

	if destination != nil && destination.NetworkNumber > 0 {
		npdu.Control.SetDestinationSpecifier(true)
		npdu.DNET = uint16(destination.NetworkNumber)
		npdu.DLEN = uint8(len(destination.MacAddress))
		npdu.DADR = destination.MacAddress
	}

	if source != nil && source.NetworkNumber > 0 && source.NetworkNumber < 0xFFFF {
		npdu.Control.SetSourceSpecifier(true)
		npdu.SNET = uint16(source.NetworkNumber)
		npdu.SLEN = uint8(len(source.MacAddress))
		npdu.SADR = source.MacAddress
	}

	return npdu
}

func (npdu *NPDU) Encode() ([]byte, error) {
	buffer := make([]byte, 0)
	buffer = append(buffer, npdu.Version)
	ctrlBuf, err := npdu.Control.Encode()
	if err != nil {
		return buffer, err
	}
	buffer = append(buffer, ctrlBuf...)

	if npdu.Control.IsDestinationSpecifier() {
		buffer = append(buffer, uint8(npdu.DNET>>8), uint8(npdu.DNET&0xFF))
		if npdu.DNET == 0xFFFF {
			buffer = append(buffer, 0x00)
		} else {
			buffer = append(buffer, npdu.DLEN)
			buffer = append(buffer, npdu.DADR...)
		}
	}

	if npdu.Control.IsSourceSpecifier() {
		buffer = append(buffer, uint8(npdu.SNET>>8), uint8(npdu.SNET&0xFF))
		buffer = append(buffer, npdu.SLEN)
		buffer = append(buffer, npdu.SADR...)
	}

	if npdu.Control.IsDestinationSpecifier() {
		buffer = append(buffer, npdu.HopCount)
	}

	if npdu.Control.IsNetworkLayerMessage() {
		buffer = append(buffer, npdu.MessageType)
		if npdu.MessageType >= 0x80 && npdu.MessageType <= 0xFF {
			buffer = append(buffer, uint8(npdu.VendorID>>8), uint8(npdu.VendorID&0xFF))
		}
	}

	return buffer, nil
}

func (npdu *NPDU) Decode(buffer []byte, offset int) (int, error) {
	length := 0
	version := buffer[offset] // always 1!!!!
	length++
	if version != npdu.Version {
		return -1, errNPDUVersion
	}
	var err error

	npdu.Control = *NewNPDUControlInformation()
	length += npdu.Control.Decode(buffer, offset+length)

	if npdu.Control.IsDestinationSpecifier() {
		npdu.DNET = binary.BigEndian.Uint16(buffer[offset+length : offset+length+2])
		length += 2
		npdu.DLEN = buffer[offset+length]
		length++
		npdu.DADR = buffer[offset+length : offset+length+int(npdu.DLEN)]
		length += int(npdu.DLEN)
		npdu.Destination, err = NewBACnetAddress(uint32(npdu.DNET), npdu.DADR, "")
		if err != nil {
			return -1, err
		}
	}

	if npdu.Control.IsSourceSpecifier() {
		npdu.SNET = binary.BigEndian.Uint16(buffer[offset+length : offset+length+2])
		length += 2
		npdu.SLEN = buffer[offset+length]
		length++
		npdu.SADR = buffer[offset+length : offset+length+int(npdu.SLEN)]
		length += int(npdu.SLEN)
		npdu.Source, err = NewBACnetAddress(uint32(npdu.SNET), npdu.SADR, "")
		if err != nil {
			return -1, err
		}
	}

	if npdu.Control.IsDestinationSpecifier() {
		npdu.HopCount = buffer[offset+length]
		length++
	}

	if npdu.Control.IsNetworkLayerMessage() {
		npdu.MessageType = buffer[offset+length]
		length++
		if npdu.MessageType >= 0x80 {
			npdu.VendorID = binary.BigEndian.Uint16(buffer[offset+length : offset+length+2])
			length += 2
		}
	}

	return length, nil
}
