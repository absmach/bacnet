package bacnet

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/absmach/bacnet/encoding"
)

type BACnetNetworkType int

const (
	Ethernet BACnetNetworkType = iota
	ARCnet
	MSTP
	PTP
	LonTalk
	IPV4
	Zigbee
	Virtual
	IPV6
	Serial
)

type ApplicationTags int

const (
	Null ApplicationTags = iota
	Boolean
	UnsignedInt
	SignedInt
	Real
	Double
	OctetString
	CharacterString
	BitString
	Enumerated
	Date
	Time
	BACnetObjectIdentifier
	Reserve1
	Reserve2
	Reserve3
)

type BACnetAddress struct {
	// BACnet Network Number.
	// NetworkNumber = 0, for local.
	NetworkNumber uint32
	// MacAddress represnets the ip address with 4 bytes and 2 bytes for port.
	// If len == 0, then this a broadcast address.
	MacAddress []byte
}

func NewBACnetAddress(networkNumber uint32, macAddress []byte, address interface{}, netType *BACnetNetworkType) *BACnetAddress {
	addr := &BACnetAddress{
		NetworkNumber: networkNumber,
		MacAddress:    macAddress,
	}

	switch addr1 := address.(type) {
	case string:
		if address != "" {
			switch *netType {
			case IPV4:
				tmp1 := strings.Split(addr1, ":")
				parts := strings.Split(tmp1[0], ".")
				var ipAddr [4]byte
				for i, part := range parts {
					val := byte(0)
					fmt.Sscanf(part, "%d", &val)
					ipAddr[i] = val
				}
				var port uint16
				fmt.Sscanf(tmp1[1], "%d", &port)
				addr.MacAddress = append(ipAddr[:], byte(port>>8), byte(port))
			case Ethernet:
				parts := strings.Split(addr1, "-")
				for _, part := range parts {
					val := byte(0)
					fmt.Sscanf(part, "%d", &val)
					addr.MacAddress = append(addr.MacAddress, val)
				}
			}
		}
	case ObjectIdentifier:
		if *netType == IPV4 {
			addr.MacAddress = make([]byte, 6)
			binary.LittleEndian.PutUint64(addr.MacAddress, uint64(addr1.Instance))
		}
	}

	return addr
}

func (ba *BACnetAddress) IPAndPort() (string, int) {
	ip := fmt.Sprintf("%d.%d.%d.%d", ba.MacAddress[0], ba.MacAddress[1], ba.MacAddress[2], ba.MacAddress[3])
	port := int(ba.MacAddress[4])<<8 + int(ba.MacAddress[5])
	return ip, port
}

func (ba *BACnetAddress) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber == byte(UnsignedInt) {
		leng += leng1
		leng1, ba.NetworkNumber = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1
	}

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber == byte(OctetString) {
		leng += leng1
		leng1, ba.MacAddress = encoding.DecodeOctetString(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1
	}

	return leng
}
