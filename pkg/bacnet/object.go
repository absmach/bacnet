package bacnet

import (
	"encoding/binary"

	"github.com/absmach/bacnet/pkg/encoding"
)

type ObjectInstance uint32

type ObjectType uint16

const (
	AnalogInput ObjectType = iota
	AnalogOutput
	AnalogValue
	BinaryInput
	BinaryOutput
	BinaryValue
	Calendar
	ObjectTypeCommand
	ObjectTypeDevice
	EventEnrollment
	File
	Group
	Loop
	MultiStateInput
	MultiStateOutput
	ObjectTypeNotificationClass
	Program
	Schedule
	Averaging
	MultiStateValue
	TrendLog
	LifeSafetyPoint
	LifeSafetyZone
	Accumulator
	PulseConverter
	EventLog
	GlobalGroup
	TrendLogMultiple
	LoadControl
	StructuredView
	AccessDoor
	Timer
	AccessCredential
	AccessPoint
	AccessRights
	AccessUser
	AccessZone
	CredentialDataInput
	NetworkSecurity
	BitStringValue
	CharacterStringValue
	DatePatternValue
	DateValue
	DateTimePatternValue
	DateTimeValue
	IntegerValue
	LargeAnalogValue
	OctetStringValue
	PositiveIntegerValue
	TimePatternValue
	TimeValue
	NotificationForwarder
	AlertEnrollment
	Channel
	LightingOutput
	BinaryLightingOutput
	NetworkPort
	ObjectTypeElevatorGroup
	Escalator
	Lift
	Staging
)

type ObjectIdentifier struct {
	Type     ObjectType
	Instance ObjectInstance
}

func (oi *ObjectIdentifier) Decode(buf []byte, offset, apdulen int) int {
	len, val := encoding.DecodeUnsigned(buf, offset, 4)
	oi.Instance = ObjectInstance(val) & ObjectInstance(encoding.MaxInstance)
	oi.Type = ObjectType(val >> encoding.InstanceBits & encoding.MaxObject)
	return len
}

func (oi *ObjectIdentifier) DecodeContext(buf []byte, offset, apdulen int, tagNumber byte) int {
	len := 0
	if encoding.DecodeIsCOntextTag(buf, offset+len, tagNumber) {
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
