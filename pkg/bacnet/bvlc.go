package bacnet

import (
	"encoding/binary"
	"errors"

	"github.com/absmach/bacnet/pkg/transport"
)

var (
	errUnsupportedTransport = errors.New("unsupported transport")
	errInvalidMessageLength = errors.New("invalid message length")
	errUnsupportedFunction  = errors.New("unsupported BVLC function")
)

type BVLCFunctions int

const (
	BVLCResult BVLCFunctions = iota
	BVLCWriteBroadcastDistributionTable
	BVLCReadBroadcastDistTable
	BVLCReadBroadcastDistTableAck
	BVLCForwardedNPDU
	BVLCRegisterForeignDevice
	BVLCReadForeignDeviceTable
	BVLCReadForeignDeviceTableAck
	BVLCDeleteForeignDeviceTableENTRY
	BVLCDistributeBroadcastToNetwok
	BVLCOriginalUnicastNPDU
	BVLCOriginalBroadcastNPDU
)

type MaxAPDU int

const (
	MaxAPDU50 MaxAPDU = iota
	MaxAPDU128
	MaxAPDU206
	MaxAPDU480
	MaxAPDU1024
	MaxAPDU1476
)

type BVLC struct {
	BVLLTypeBACnetIP byte
	BVLCHeaderLength byte
	BVLCMaxAPDU      MaxAPDU
}

func NewBVLC(transprt transport.Transport) *BVLC {
	bvlc := &BVLC{
		BVLLTypeBACnetIP: 0x81,
		BVLCHeaderLength: 4,
	}

	if transprt == transport.IP {
		bvlc.BVLCMaxAPDU = MaxAPDU1476
	}

	return bvlc
}

func (bvlc *BVLC) Decode(buffer []byte, offset int) (int, byte, uint16, error) {
	msgType := buffer[0]
	function := BVLCFunctions(buffer[1])
	msgLength := binary.BigEndian.Uint16(buffer[2:4])

	if msgType != bvlc.BVLLTypeBACnetIP || msgLength != uint16(len(buffer)) {
		return 0, 0, 0, errUnsupportedTransport
	}

	switch function {
	case BVLCResult:
		return 4, byte(function), msgLength, nil
	case BVLCOriginalUnicastNPDU:
		return 4, byte(function), msgLength, nil
	case BVLCOriginalBroadcastNPDU:
		return 4, byte(function), msgLength, nil
	case BVLCForwardedNPDU:
		// Handle this case
	case BVLCDistributeBroadcastToNetwok:
		// Handle this case
	case BVLCRegisterForeignDevice:
		// Handle this case
	case BVLCReadForeignDeviceTable:
		// Handle this case
	case BVLCDeleteForeignDeviceTableENTRY:
		// Handle this case
	case BVLCReadBroadcastDistTable:
		// Handle this case
	case BVLCWriteBroadcastDistributionTable:
		// Handle this case
	default:
		return -1, 0, 0, errUnsupportedFunction
	}

	return 0, 0, 0, errors.New("todo")
}

func (bvlc BVLC) First4BytesHeaderEncode(function BVLCFunctions, msgLength uint16) []byte {
	b := make([]byte, 4)
	b[0] = bvlc.BVLLTypeBACnetIP
	b[1] = byte(function)
	binary.BigEndian.PutUint16(b[2:4], msgLength)
	return b
}

func (bvlc BVLC) Encode(function BVLCFunctions, msgLength uint16) []byte {
	return bvlc.First4BytesHeaderEncode(function, msgLength)
}
