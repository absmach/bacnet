package bacnet

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/absmach/bacnet/internal"
	"github.com/absmach/bacnet/pkg/encoding"
)

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

type ReadPropertyACK struct {
	ObjectIdentifier   ObjectIdentifier
	PropertyIdentifier interface{}
	PropertyArrayIndex uint32
	PropertyValue      []BACnetValue
}

func (r *ReadPropertyACK) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0

	// 0 object_identifier
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		r.ObjectIdentifier = ObjectIdentifier{}
		leng1 := r.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)
		leng += leng1
	} else {
		return -1, errors.New("decoding error for object_identifier")
	}

	// 2 propertyidentifier
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		PropertyID := encoding.PropertyList
		leng1, propID := encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &PropertyID)
		r.PropertyIdentifier = propID
		leng += leng1
	} else {
		return -1, errors.New("decoding error for property_identifier")
	}

	// 2 property_array_index
	if encoding.IsContextTag(buffer, offset+leng, 2) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, r.PropertyArrayIndex = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	}

	// tag 3 property-value
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 3) {
		leng++
		r.PropertyValue = make([]BACnetValue, 0)
		for !encoding.IsClosingTagNumber(buffer, offset+leng, 3) && leng < apduLen {
			bValue := BACnetValue{}
			propId := r.PropertyIdentifier.(encoding.PropertyIdentifier)
			leng1, err := bValue.Decode(buffer, offset+leng, apduLen-leng, &r.ObjectIdentifier.Type, &propId)
			if err != nil {
				return -1, err
			}
			leng += leng1
			r.PropertyValue = append(r.PropertyValue, bValue)
		}
		if encoding.IsClosingTagNumber(buffer, offset+leng, 3) {
			leng++
		} else {
			return -1, errors.New("decoding error for property_value")
		}
	} else {
		return -1, errors.New("decoding error for property_value")
	}

	return leng, nil
}

type BACnetValue struct {
	Tag   *ApplicationTags
	Value interface{}
}

func (bv *BACnetValue) Decode(buffer []byte, offset, apduLen int, objType *encoding.ObjectType, propID *encoding.PropertyIdentifier) (int, error) {
	length := 0
	var err error

	if !encoding.IsContextSpecific(buffer[offset]) {
		tagLen, tagNumber, lenValueType := encoding.DecodeTagNumberAndValue(buffer, offset)
		if tagLen > 0 {
			ttag := ApplicationTags(tagNumber)
			bv.Tag = &ttag
			length += tagLen

			decodeLen := 0

			switch *bv.Tag {
			case Null:
				bv.Value = nil
				decodeLen = 0
			case Boolean:
				if lenValueType > 0 {
					bv.Value = true
				} else {
					bv.Value = false
				}
			case UnsignedInt:
				if *propID == encoding.RoutingTable {
					bv.Tag = nil
					bv.Value = &RouterEntry{}
					length--
					decodeLen, err = bv.Value.(*RouterEntry).Decode(buffer, offset+length, apduLen)
					if err != nil {
						return -1, err
					}
				} else if *propID == encoding.ActiveVtSessions {
					bv.Tag = nil
					bv.Value = &BACnetVTSession{}
					length--
					decodeLen = bv.Value.(*BACnetVTSession).Decode(buffer, offset+length, apduLen)
				} else if *propID == encoding.ThreatLevel || *propID == encoding.ThreatAuthority {
					bv.Tag = nil
					bv.Value = &BACnetAccessThreatLevel{}
					length--
					decodeLen = bv.Value.(*BACnetAccessThreatLevel).Decode(buffer, offset+length, apduLen)
				} else {
					var uintVal uint32
					decodeLen, uintVal = encoding.DecodeUnsigned(buffer, offset+length, int(lenValueType))
					bv.Value = uintVal
				}
			case SignedInt:
				var intValue int
				decodeLen, intValue = encoding.DecodeSigned(buffer, offset+length, int(lenValueType))
				bv.Value = intValue
			case Real:
				var floatValue float32
				decodeLen, floatValue = encoding.DecodeRealSafe(buffer, offset+length, int(lenValueType))
				bv.Value = floatValue
			case Double:
				var doubleValue float64
				decodeLen, doubleValue = encoding.DecodeDoubleSafe(buffer, offset+length, int(lenValueType))
				bv.Value = doubleValue
			case OctetString:
				var octetValue []byte
				decodeLen, octetValue = encoding.DecodeOctetString(buffer, offset+length, int(lenValueType))
				bv.Value = octetValue
			case CharacterString:
				var stringValue string
				decodeLen, stringValue = encoding.DecodeCharacterString(buffer, offset+length, apduLen, int(lenValueType))
				bv.Value = stringValue
			case BitString:
				switch *propID {
				case encoding.RecipientList:
					bv.Tag = nil
					bv.Value = &BACnetDestination{}
					length--
					decodeLen = bv.Value.(*BACnetDestination).Decode(buffer, offset+length, apduLen)
				case encoding.StatusFlags:
					bv.Tag = nil
					bitValue := &BACnetStatusFlags{}
					decodeLen = bitValue.Decode(buffer, offset, int(lenValueType))
					bv.Value = bitValue
				case encoding.EventEnable, encoding.AckedTransitions:
					bv.Tag = nil
					bitValue := &BACnetEventTransitionBits{}
					decodeLen = bitValue.Decode(buffer, offset, int(lenValueType))
					bv.Value = bitValue
				case encoding.LimitEnable:
					bv.Tag = nil
					bitValue := &BACnetLimitEnable{}
					decodeLen = bitValue.Decode(buffer, offset, int(lenValueType))
					bv.Value = bitValue
				case encoding.ProtocolObjectTypesSupported:
					bv.Tag = nil
					bitValue := &BACnetObjectTypesSupported{}
					decodeLen = bitValue.Decode(buffer, offset, int(lenValueType))
					bv.Value = bitValue
				case encoding.ProtocolServicesSupported:
					bv.Tag = nil
					bitValue := &BACnetServicesSupported{}
					decodeLen = bitValue.Decode(buffer, offset, int(lenValueType))
					bv.Value = bitValue
				default:
					bitValue := &BACnetBitString{}
					decodeLen = bitValue.Decode(buffer, offset, int(lenValueType))
					bv.Value = bitValue
				}
			case Enumerated:
				decodeLen, bv.Value = encoding.DecodeEnumerated(buffer, offset+length, lenValueType, objType, propID)
			case Date:
				switch *propID {
				case encoding.EffectivePeriod:
					bv.Tag = nil
					bv.Value = &BACnetDateRange{}
					length--
					decodeLen, err = bv.Value.(*BACnetDateRange).Decode(buffer, offset+length, apduLen)
					if err != nil {
						return -1, err
					}
				case encoding.MinimumValueTimestamp,
					encoding.MaximumValueTimestamp,
					encoding.ChangeOfStateTime,
					encoding.TimeOfStateCountReset,
					encoding.TimeOfActiveTimeReset,
					encoding.ModificationDate,
					encoding.UpdateTime,
					encoding.CountChangeTime,
					encoding.StartTime,
					encoding.StopTime,
					encoding.LastCredentialAddedTime,
					encoding.LastCredentialRemovedTime,
					encoding.ActivationTime,
					encoding.ExpiryTime,
					encoding.LastUseTime,
					encoding.TimeOfStrikeCountReset,
					encoding.ValueChangeTime:
					bv.Tag = nil
					bv.Value = &DateTime{}
					length--
					decodeLen = bv.Value.(*DateTime).Decode(buffer, offset+length)
				default:
					decodeLen, bv.Value = encoding.DecodeDateSafe(buffer, offset+length, int(lenValueType))
				}
				if (*objType == encoding.DateTimeValue || *objType == encoding.TimePatternValue) && (*propID == encoding.PresentValue || *propID == encoding.RelinquishDefault) {
					decodeLen, bv.Value = encoding.DecodeDateSafe(buffer, offset+length, int(lenValueType))
				}
			case Time:
				decodeLen, bv.Value = encoding.DecodeBACnetTimeSafe(buffer, offset+length, int(lenValueType))
			case BACnetObjectIdentifier:
				if *propID == encoding.LastKeyServer ||
					*propID == encoding.ManualSlaveAddressBinding ||
					*propID == encoding.SlaveAddressBinding ||
					*propID == encoding.DeviceAddressBinding {
					bv.Tag = nil
					bv.Value = &BACnetAddressBinding{}
					length--
					decodeLen = bv.Value.(*BACnetAddressBinding).Decode(buffer, offset+length, apduLen)
				} else {
					var objectType encoding.ObjectType
					var instance uint32
					decodeLen, objectType, instance = encoding.DecodeObjectIDSafe(buffer, offset+length, lenValueType)
					bv.Value = ObjectIdentifier{Type: objectType, Instance: ObjectInstance(instance)}
				}
			default:
				log.Println("Unhandled tag:", bv.Tag)
				length = apduLen
			}

			if decodeLen < 0 {
				return -1, fmt.Errorf("no tags decoded")
			}
			length += decodeLen
		}
	} else {
		switch *propID {
		case encoding.BacnetIpGlobalAddress, encoding.FdBbmdAddress:
			bv.Value = &BACnetHostNPort{}
			length1, err := bv.Value.(*BACnetHostNPort).Decode(buffer, offset+length, apduLen-length)
			if err != nil {
				return -1, err
			}
			length += length1
		case encoding.UtcTimeSynchronizationRecipients,
			encoding.RestartNotificationRecipients,
			encoding.TimeSynchronizationRecipients,
			encoding.CovuRecipients:
			bv.Value = &BACnetRecipient{}
			length += bv.Value.(*BACnetRecipient).Decode(buffer, offset+length, apduLen-length)
		case encoding.KeySets:
			bv.Value = &BACnetSecurityKeySet{}
			length1, err := bv.Value.(*BACnetSecurityKeySet).Decode(buffer, offset+length, apduLen-length)
			if err != nil {
				return -1, err
			}
			length += length1
		case encoding.EventTimeStamps,
			encoding.LastCommandTime,
			encoding.CommandTimeArray,
			encoding.LastRestoreTime,
			encoding.TimeOfDeviceRestart,
			encoding.AccessEventTime,
			encoding.UpdateTime:
			bv.Value = &BACnetTimeStamp{}
			length1, err := bv.Value.(*BACnetTimeStamp).Decode(buffer, offset+length, apduLen-length)
			if err != nil {
				return -1, err
			}
			length += length1
		case encoding.ListOfGroupMembers:
			bv.Value = &ReadAccessSpecification{}
			length, err = bv.Value.(*ReadAccessSpecification).Decode(buffer, offset+length, apduLen-length)
			if err != nil {
				return -1, err
			}
		case encoding.ListOfObjectPropertyReferences:
			bv.Value = &BACnetDeviceObjectPropertyReference{}
			length, err = bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
			if err != nil {
				return -1, err
			}
		case encoding.MemberOf,
			encoding.ZoneMembers,
			encoding.DoorMembers,
			encoding.SubordinateList,
			encoding.Represents,
			encoding.AccessEventCredential,
			encoding.AccessDoors,
			encoding.ZoneTo,
			encoding.ZoneFrom,
			encoding.CredentialsInZone,
			encoding.LastCredentialAdded,
			encoding.LastCredentialRemoved,
			encoding.EntryPoints,
			encoding.ExitPoints,
			encoding.Members,
			encoding.Credentials,
			encoding.Accompaniment,
			encoding.BelongsTo,
			encoding.LastAccessPoint,
			encoding.EnergyMeterRef:
			bv.Value = &BACnetDeviceObjectReference{}
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case encoding.EventAlgorithmInhibitRef,
			encoding.InputReference,
			encoding.ManipulatedVariableReference,
			encoding.ControlledVariableReference:
			bv.Value = &BACnetObjectPropertyReference{}
			length += bv.Value.(*BACnetObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case encoding.LoggingRecord:
			bv.Value = &BACnetAccumulatorRecord{}
			length, err = bv.Value.(*BACnetAccumulatorRecord).Decode(buffer, offset+length, apduLen-length)
			if err != nil {
				return -1, err
			}
		case encoding.Action:
			bv.Value = &BACnetActionList{}
			length += bv.Value.(*BACnetActionList).Decode(buffer, offset+length, apduLen-length)
		case encoding.Scale:
			bv.Value = &BACnetScale{}
			length += bv.Value.(*BACnetScale).Decode(buffer, offset+length, apduLen-length)
		case encoding.LightingCommand:
			bv.Value = &BACnetLightingCommand{}
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case encoding.Prescale:
			bv.Value = &BACnetPrescale{}
			length += bv.Value.(*BACnetPrescale).Decode(buffer, offset+length, apduLen-length)
		case encoding.RequestedShedLevel,
			encoding.ExpectedShedLevel,
			encoding.ActualShedLevel:
			bv.Value = &BACnetShedLevel{}
			length += bv.Value.(*BACnetShedLevel).Decode(buffer, offset+length, apduLen-length)
		case encoding.LogBuffer:
			switch *objType {
			case encoding.TrendLog:
				bv.Value = &BACnetLogRecord{}
				length += bv.Value.(*BACnetLogRecord).Decode(buffer, offset+length, apduLen-length, nil, nil)
			case encoding.EventLog:
				bv.Value = &BACnetEventLogRecord{}
				length += bv.Value.(*BACnetEventLogRecord).Decode(buffer, offset+length, apduLen-length)
			}
		case encoding.DateList:
			bv.Value = &BACnetCalendarEntry{}
			length += bv.Value.(*BACnetCalendarEntry).Decode(buffer, offset+length, apduLen-length)
		case encoding.PresentValue:
			switch *objType {
			case encoding.Group:
				bv.Value = &ReadAccessResult{}
				length += bv.Value.(*ReadAccessResult).Decode(buffer, offset+length, apduLen-length)
			case encoding.Channel:
				bv.Value = &BACnetChannelValue{}
				length += bv.Value.(*BACnetChannelValue).Decode(buffer, offset+length, apduLen-length)
			case encoding.GlobalGroup:
				bv.Value = &BACnetPropertyAccessResult{}
				length += bv.Value.(*BACnetPropertyAccessResult).Decode(buffer, offset+length, apduLen-length)
			case encoding.CredentialDataInput:
				bv.Value = &BACnetAuthenticationFactor{}
				length += bv.Value.(*BACnetAuthenticationFactor).Decode(buffer, offset+length, apduLen-length)
			}
		case encoding.NegativeAccessRules,
			encoding.PositiveAccessRules:
			bv.Value = &BACnetAccessRule{}
			length += bv.Value.(*BACnetAccessRule).Decode(buffer, offset+length, apduLen-length)
		case encoding.Tags:
			bv.Value = &BACnetNameValue{}
			length += bv.Value.(*BACnetNameValue).Decode(buffer, offset+length, apduLen-length)
		case encoding.SubordinateTags:
			bv.Value = &BACnetNameValueCollection{}
			length += bv.Value.(*BACnetNameValueCollection).Decode(buffer, offset+length, apduLen-length)
		case encoding.NetworkAccessSecurityPolicies:
			bv.Value = &BACnetNetworkSecurityPolicy{}
			length += bv.Value.(*BACnetNetworkSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case encoding.PortFilter:
			bv.Value = &BACnetPortPermission{}
			length += bv.Value.(*BACnetPortPermission).Decode(buffer, offset+length, apduLen-length)
		case encoding.PriorityArray:
			bv.Value = &BACnetPriorityArray{}
			length += bv.Value.(*BACnetPriorityArray).Decode(buffer, offset+length, apduLen-length)
		case encoding.ProcessIdentifierFilter:
			bv.Value = &BACnetProcessIdSelection{}
			length += bv.Value.(*BACnetProcessIdSelection).Decode(buffer, offset+length, apduLen-length)
		case encoding.SetpointReference:
			bv.Value = &BACnetSetpointReference{}
			length += bv.Value.(*BACnetSetpointReference).Decode(buffer, offset+length, apduLen-length)
		case encoding.ExceptionSchedule:
			bv.Value = &BACnetSpecialEvent{}
			length += bv.Value.(*BACnetSpecialEvent).Decode(buffer, offset+length, apduLen-length)
		case encoding.StateChangeValues:
			bv.Value = &BACnetTimerStateChangeValue{}
			length += bv.Value.(*BACnetTimerStateChangeValue).Decode(buffer, offset+length, apduLen-length)
		case encoding.ValueSource, encoding.ValueSourceArray:
			bv.Value = &BACnetValueSource{}
			length += bv.Value.(*BACnetValueSource).Decode(buffer, offset+length, apduLen-length)
		case encoding.VirtualMacAddressTable:
			bv.Value = &BACnetVMACEntry{}
			length += bv.Value.(*BACnetVMACEntry).Decode(buffer, offset+length, apduLen-length)
		case encoding.AssignedAccessRights:
			bv.Value = &BACnetAssignedAccessRights{}
			length += bv.Value.(*BACnetAssignedAccessRights).Decode(buffer, offset+length, apduLen-length)
		case encoding.AssignedLandingCalls:
			bv.Value = &BACnetAssignedLandingCalls{}
			length += bv.Value.(*BACnetAssignedLandingCalls).Decode(buffer, offset+length, apduLen-length)
		case encoding.AccessEventAuthenticationFactor:
			bv.Value = &BACnetAuthenticationFactor{}
			length += bv.Value.(*BACnetAuthenticationFactor).Decode(buffer, offset+length, apduLen-length)
		case encoding.SupportedFormats:
			bv.Value = &BACnetAuthenticationFactorFormat{}
			length += bv.Value.(*BACnetAuthenticationFactorFormat).Decode(buffer, offset+length, apduLen-length)
		case encoding.AuthenticationPolicyList:
			bv.Value = &BACnetAuthenticationPolicy{}
			length += bv.Value.(*BACnetAuthenticationPolicy).Decode(buffer, offset+length, apduLen-length)
		case encoding.ActiveCovSubscriptions:
			bv.Value = &BACnetCOVSubscription{}
			length += bv.Value.(*BACnetCOVSubscription).Decode(buffer, offset+length, apduLen-length)
		case encoding.AuthenticationFactors:
			bv.Value = &BACnetCredentialAuthenticationFactor{}
			length += bv.Value.(*BACnetCredentialAuthenticationFactor).Decode(buffer, offset+length, apduLen-length)
		case encoding.WeeklySchedule:
			bv.Value = &BACnetDailySchedule{}
			length += bv.Value.(*BACnetDailySchedule).Decode(buffer, offset+length, apduLen-length)
		case encoding.SubscribedRecipients:
			bv.Value = &BACnetEventNotificationSubscription{}
			length += bv.Value.(*BACnetEventNotificationSubscription).Decode(buffer, offset+length, apduLen-length)
		case encoding.EventParameters:
			bv.Value = &BACnetEventParameter{}
			length += bv.Value.(*BACnetEventParameter).Decode(buffer, offset+length, apduLen-length)
		case encoding.FaultParameters:
			bv.Value = &BACnetFaultParameter{}
			length += bv.Value.(*BACnetFaultParameter).Decode(buffer, offset+length, apduLen-length)
		default:
			bv.Value = nil
		}
	}
	return length, nil
}

func (bv *BACnetValue) Encode() []byte {
	if bv.Tag == nil {
		return nil
	} else {
		switch *bv.Tag {
		case Boolean:
			return encoding.EncodeApplicationBoolean(bv.Value.(bool))
		case UnsignedInt:
			return encoding.EncodeApplicationUnsigned(bv.Value.(uint32))
		case SignedInt:
			return encoding.EncodeApplicationSigned(bv.Value.(int32))
		case Real:
			return encoding.EncodeApplicationReal(bv.Value.(float32))
		case Double:
			return encoding.EncodeApplicationDouble(bv.Value.(float64))
		case OctetString:
			return encoding.EncodeApplicationOctetString(bv.Value.([]byte), 0, len(bv.Value.([]byte)))
		case CharacterString:
			return encoding.EncodeApplicationCharacterString(bv.Value.(string))
		case BitString:
			return encoding.EncodeApplicationBitString(bv.Value)
		case Enumerated:
			return encoding.EncodeApplicationEnumerated(bv.Value.(uint32))
		case Date:
			return encoding.EncodeApplicationDate(bv.Value.(time.Time))
		case Time:
			return encoding.EncodeApplicationTime(bv.Value.(time.Time))
		case BACnetObjectIdentifier:
			return bv.Value.(*ObjectIdentifier).EncodeApp()
		default:
			switch bv.Value.(type) {
			case int:
				return encoding.EncodeApplicationEnumerated(uint32(bv.Value.(int)))
			}
			log.Printf("Unsupported BACnetApplicationTag: %v", bv.Tag)
			return nil
		}
	}
}

// BACnetRouterEntryStatus is an enumeration for the status of BACnetRouterEntry.
type BACnetRouterEntryStatus int

const (
	Available BACnetRouterEntryStatus = iota
	BACnetRouterEntryStatusBusy
	Disconnected
)

// BACnetRouterEntry represents a BACnet router entry.
type RouterEntry struct {
	NetworkNumber    uint32
	MACAddress       []byte
	Status           BACnetRouterEntryStatus
	PerformanceIndex uint32
}

// Decode decodes a RouterEntry from an encoded byte buffer.
func (entry *RouterEntry) Decode(buffer []byte, offset, apduLen int) (int, error) {
	var length int

	// network_number
	length1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset)
	if tagNumber != byte(encoding.UnsignedInt) {
		return -1, errors.New("Error decoding network_number")
	}
	length += length1
	length1, entry.NetworkNumber = encoding.DecodeUnsigned(buffer, offset+length, int(lenValue))
	length += length1

	// mac_address
	length1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+length)
	if tagNumber != byte(encoding.OctetString) {
		return -1, errors.New("Error decoding mac_address")
	}
	length += length1
	length1, entry.MACAddress = encoding.DecodeOctetString(buffer, offset+length, int(lenValue))
	length += length1

	// status
	length1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+length)
	if tagNumber != byte(encoding.Enumerated) {
		return -1, errors.New("Error decoding status")
	}
	length += length1
	length1, Val := encoding.DecodeUnsigned(buffer, offset+length, int(lenValue))
	length += length1
	entry.Status = BACnetRouterEntryStatus(Val)

	// performance_index (optional)
	if offset < apduLen {
		length1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+length)
		if tagNumber != byte(encoding.UnsignedInt) {
			length += length1
			length1, entry.PerformanceIndex = encoding.DecodeUnsigned(buffer, offset+length, int(lenValue))
			length += length1
		}
	}

	return length, nil
}

type BACnetVTSession struct {
	LocalVTSessionID  int
	RemoteVTSessionID int
	RemoteVTAddress   BACnetAddress
}

// decode method for BACnetVTSession
func (b *BACnetVTSession) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decode logic here
	return -1
}

// BACnetAccessThreatLevel struct definition
type BACnetAccessThreatLevel struct {
	Value int
}

// decode method for BACnetAccessThreatLevel
func (b *BACnetAccessThreatLevel) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decode logic here
	return -1
}

type BACnetDestination struct {
	ValidDays                   *BACnetDaysOfWeek
	FromTime                    time.Time
	ToTime                      time.Time
	Recipient                   *BACnetRecipient
	ProcessIdentifier           uint32
	IssueConfirmedNotifications bool
	Transitions                 *BACnetEventTransitionBits
}

func (b *BACnetDestination) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != byte(encoding.BitString) {
		return -1
	}
	leng += leng1
	b.ValidDays = &BACnetDaysOfWeek{}

	leng1 = b.ValidDays.Decode(buffer, offset+leng, int(lenValue))

	if leng1 < 0 {
		return -1
	}
	leng += leng1

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != byte(encoding.Time) {
		return -1
	}
	leng += leng1
	leng1, b.FromTime = encoding.DecodeBACnetTimeSafe(buffer, offset+leng, int(lenValue))

	leng += leng1

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != byte(encoding.Time) {
		return -1
	}
	leng += leng1
	leng1, b.ToTime = encoding.DecodeBACnetTimeSafe(buffer, offset+leng, int(lenValue))

	leng += leng1

	b.Recipient = &BACnetRecipient{}
	leng1 = b.Recipient.Decode(buffer, offset+leng, apduLen-leng)

	if leng1 < 0 {
		return -1
	}
	leng += leng1

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != byte(encoding.UnsignedInt) {
		return -1
	}
	leng += leng1
	leng1, b.ProcessIdentifier = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))

	leng += leng1

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != byte(encoding.Boolean) {
		return -1
	}
	leng += leng1
	if lenValue > 0 {
		b.IssueConfirmedNotifications = true
	} else {
		b.IssueConfirmedNotifications = false
	}

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != byte(encoding.BitString) {
		return -1
	}
	leng += leng1

	b.Transitions = &BACnetEventTransitionBits{}
	leng1 = b.Transitions.Decode(buffer, offset+leng, int(lenValue))
	if leng1 < 0 {
		return -1
	}
	leng += leng1

	return leng
}

type BACnetDaysOfWeek struct {
	unusedBits byte
	bitString  BACnetBitString
	monday     bool
	tuesday    bool
	wednesday  bool
	thursday   bool
	friday     bool
	saturday   bool
	sunday     bool
}

func NewBACnetDaysOfWeek() *BACnetDaysOfWeek {
	return &BACnetDaysOfWeek{
		unusedBits: 1,
		bitString:  *NewBACnetBitString(1, *internal.NewBitArray(8)),
	}
}

func (d *BACnetDaysOfWeek) Decode(buffer []byte, offset int, apduLen int) int {
	d.bitString = BACnetBitString{}
	return d.bitString.Decode(buffer, offset, apduLen)
}

func (d *BACnetDaysOfWeek) SetDay(day int, value bool) error {
	if day < 0 || day > 6 {
		return fmt.Errorf("Day index out of range")
	}
	d.bitString.Value.Set(day, value)
	return nil
}

func (d *BACnetDaysOfWeek) GetDay(day int) (bool, error) {
	if day < 0 || day > 6 {
		return false, fmt.Errorf("Day index out of range")
	}
	return d.bitString.Value.Get(day) == true, nil
}

type BACnetBitString struct {
	UnusedBits byte
	Value      internal.BitArray
}

func NewBACnetBitString(unusedBits byte, value internal.BitArray) *BACnetBitString {
	return &BACnetBitString{
		UnusedBits: unusedBits,
		Value:      value,
	}
}

func (b *BACnetBitString) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	if apduLen > 0 {
		b.UnusedBits = buffer[offset]
		leng += 1
		b.Value = *internal.NewBitArray((apduLen - 1) * 8)
		bit := 0
		for i := 1; i < apduLen; i++ {
			for i2 := 0; i2 < 8; i2++ {
				b.Value.Set(bit, buffer[offset+i]&(1<<(7-i2)) != 0)
				bit++
			}
		}
	}
	return apduLen
}

type BACnetRecipient struct {
	Value interface{}
}

func (br *BACnetRecipient) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)

	if tagNumber == 0 {
		// device_identifier
		leng += leng1
		br.Value = &ObjectIdentifier{}
		leng += br.Value.(*ObjectIdentifier).Decode(buffer, offset+leng, int(lenValue))
	} else if tagNumber == 1 {
		// address
		br.Value = &BACnetAddress{}
		leng += br.Value.(*BACnetAddress).Decode(buffer, offset+leng, int(lenValue))
	} else {
		return -1
	}

	return leng
}

// BACnetEventTransitionBits represents a BACnet event transition bits structure.
type BACnetEventTransitionBits struct {
	UnusedBits uint8
	BitString  *BACnetBitString
}

// NewBACnetEventTransitionBits creates a new BACnet event transition bits instance.
func NewBACnetEventTransitionBits() *BACnetEventTransitionBits {
	return &BACnetEventTransitionBits{
		UnusedBits: 5,
		BitString:  NewBACnetBitString(5, *internal.NewBitArray(5)),
	}
}

// Decode decodes the bit string from a buffer.
func (e *BACnetEventTransitionBits) Decode(buffer []byte, offset, apduLen int) int {
	bitString := NewBACnetBitString(0, internal.BitArray{})
	decodedLen := bitString.Decode(buffer, offset, apduLen)

	e.BitString = bitString
	return decodedLen
}

// ToOffNormal returns the value of ToOffNormal property.
func (e *BACnetEventTransitionBits) ToOffNormal() bool {
	return e.BitString.Value.Get(0) == true
}

// SetToOffNormal sets the value of ToOffNormal property.
func (e *BACnetEventTransitionBits) SetToOffNormal(a bool) {
	e.BitString.Value.Set(0, a)
}

// ToFault returns the value of ToFault property.
func (e *BACnetEventTransitionBits) ToFault() bool {
	return e.BitString.Value.Get(1) == true
}

// SetToFault sets the value of ToFault property.
func (e *BACnetEventTransitionBits) SetToFault(a bool) {
	e.BitString.Value.Set(1, a)
}

// ToNormal returns the value of ToNormal property.
func (e *BACnetEventTransitionBits) ToNormal() bool {
	return e.BitString.Value.Get(2) == true
}

// SetToNormal sets the value of ToNormal property.
func (e *BACnetEventTransitionBits) SetToNormal(a bool) {
	e.BitString.Value.Set(2, a)
}

// BACnetStatusFlags represents a BACnet status flags.
type BACnetStatusFlags struct {
	unusedbits   int
	bitstring    BACnetBitString
	inalarm      bool
	fault        bool
	overridden   bool
	outofservice bool
}

// NewBACnetStatusFlags creates a new BACnetStatusFlags instance.
func NewBACnetStatusFlags() *BACnetStatusFlags {
	return &BACnetStatusFlags{
		unusedbits:   4,
		bitstring:    *NewBACnetBitString(4, *internal.NewBitArrayFromByte(0x00)),
		inalarm:      false,
		fault:        false,
		overridden:   false,
		outofservice: false,
	}
}

// decode decodes BACnetStatusFlags from a buffer.
func (s *BACnetStatusFlags) Decode(buffer []byte, offset, apduLen int) int {
	s.bitstring = *NewBACnetBitString(byte(s.unusedbits), *internal.NewBitArrayFromByte(0x00))
	return s.bitstring.Decode(buffer, offset, apduLen)
}

// InAlarm returns the inalarm property.
func (s *BACnetStatusFlags) InAlarm() bool {
	return s.bitstring.Value.Get(0)
}

// SetInAlarm sets the inalarm property.
func (s *BACnetStatusFlags) SetInAlarm(a bool) {
	s.bitstring.Value.Set(0, a)
}

// Fault returns the fault property.
func (s *BACnetStatusFlags) Fault() bool {
	return s.bitstring.Value.Get(1)
}

// SetFault sets the fault property.
func (s *BACnetStatusFlags) SetFault(a bool) {
	s.bitstring.Value.Set(1, a)
}

// Overridden returns the overridden property.
func (s *BACnetStatusFlags) Overridden() bool {
	return s.bitstring.Value.Get(2)
}

// SetOverridden sets the overridden property.
func (s *BACnetStatusFlags) SetOverridden(a bool) {
	s.bitstring.Value.Set(2, a)
}

// OutOfService returns the outofservice property.
func (s *BACnetStatusFlags) OutOfService() bool {
	return s.bitstring.Value.Get(3)
}

// SetOutOfService sets the outofservice property.
func (s *BACnetStatusFlags) SetOutOfService(a bool) {
	s.bitstring.Value.Set(3, a)
}

type BACnetLimitEnable struct {
	unusedBits      uint8
	bitString       BACnetBitString
	lowLimitEnable  bool
	highLimitEnable bool
}

func NewBACnetLimitEnable() *BACnetLimitEnable {
	return &BACnetLimitEnable{
		unusedBits:      6,
		bitString:       *NewBACnetBitString(6, *internal.NewBitArrayFromByte(0x00)),
		lowLimitEnable:  false,
		highLimitEnable: false,
	}
}

func (b *BACnetLimitEnable) Decode(buffer []byte, offset, apduLen int) int {
	b.bitString = *NewBACnetBitString(0, *internal.NewBitArrayFromByte(0x00))
	return b.bitString.Decode(buffer, offset, apduLen)
}

func (b *BACnetLimitEnable) LowLimitEnable() bool {
	return b.bitString.Value.Get(0)
}

func (b *BACnetLimitEnable) SetLowLimitEnable(a bool) {
	b.bitString.Value.Set(0, a)
}

func (b *BACnetLimitEnable) HighLimitEnable() bool {
	return b.bitString.Value.Get(1)
}

func (b *BACnetLimitEnable) SetHighLimitEnable(a bool) {
	b.bitString.Value.Set(1, a)
}

type BACnetObjectTypesSupported struct {
	unusedbits uint8
	bitstring  BACnetBitString
}

type ObjectTypesSupportedProperty int

const (
	AnalogInput ObjectTypesSupportedProperty = iota
	AanalofOutput
	AnalogValue
	BinaryInput
	BinaryOutput
	// TODO Add other properties here
)

func NewBACnetObjectTypesSupported() *BACnetObjectTypesSupported {
	return &BACnetObjectTypesSupported{
		unusedbits: 3,
		bitstring:  *NewBACnetBitString(3, *internal.NewBitArray(64)),
	}
}

func (b *BACnetObjectTypesSupported) Set(property ObjectTypesSupportedProperty, value bool) {
	b.bitstring.Value.Set(int(property), value)
}

func (b *BACnetObjectTypesSupported) Get(property ObjectTypesSupportedProperty) bool {
	return b.bitstring.Value.Get(int(property))
}

func (b *BACnetObjectTypesSupported) Decode(buf []byte, offset, apduLen int) int {
	return b.bitstring.Decode(buf, offset, apduLen)
}

type BACnetServicesSupported struct {
	unusedbits uint8
	bitstring  BACnetBitString
}

type ServicesSupportedProperty int

// TODO check index sequence
const (
	acknowledgeAlarm ServicesSupportedProperty = iota
	confirmedCOVNotification
	confirmedCOVNotificationMultiple
	confirmedEventNotification
	getAlarmSummary
	getEnrollmentSummary
	getEventInformation
	lifeSafetyOperation
	subscribeCOV
	subscribeCOVProperty
	subscribeCOVPropertyMultiple
	atomicReadFile
	atomicWriteFile
	addListElement
	removeListElement
	createObject
	deleteObject
	readProperty
	readPropertyMultiple
	readRange
	writeGroup
	writeProperty
	writePropertyMultiple
	deviceCommunicationControl
	confirmedPrivateTransfer
	confirmedTextMessage
	reinitializeDevice
	vtOpen
	vtClose
	vtData
	whoAmI
	youAre
	iAm
	iHave
	unconfirmedCOVNotification
	unconfirmedCOVNotificationMultiple
	unconfirmedEventNotification
	unconfirmedPrivateTransfer
	unconfirmedTextMessage
	timeSynchronization
	utcTimeSynchronization
	whoHas
	whoIs
)

func NewBACnetServicesSupported() *BACnetServicesSupported {
	return &BACnetServicesSupported{
		unusedbits: 7,
		bitstring:  *NewBACnetBitString(7, *internal.NewBitArrayFromByte(0x00000000000000)),
	}
}

func (b *BACnetServicesSupported) Set(property ServicesSupportedProperty, value bool) {
	b.bitstring.Value.Set(int(property), value)
}

func (b *BACnetServicesSupported) Get(property ServicesSupportedProperty) bool {
	return b.bitstring.Value.Get(int(property))
}

func (b *BACnetServicesSupported) Decode(buf []byte, offset, apduLen int) int {
	return b.bitstring.Decode(buf, offset, apduLen)
}

// BACnetDateRange is a struct representing a date range in BACnet.
type BACnetDateRange struct {
	StartDate time.Time
	EndDate   time.Time
}

// Decode decodes a BACnetDateRange from the given buffer, offset, and length.
func (dr *BACnetDateRange) Decode(buffer []byte, offset, apduLen int) (int, error) {
	var leng int

	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber == byte(Date) {
		leng += leng1
		leng1, startDate := encoding.DecodeDateSafe(buffer, offset+leng, int(lenValue))
		dr.StartDate = startDate
		leng += leng1
	} else {
		return -1, fmt.Errorf("Unexpected tag number: %v", tagNumber)
	}

	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber == byte(Date) {
		leng += leng1
		leng1, endDate := encoding.DecodeDateSafe(buffer, offset+leng, int(lenValue))

		dr.EndDate = endDate
		leng += leng1
	} else {
		return -1, fmt.Errorf("Unexpected tag number: %v", tagNumber)
	}

	return leng, nil
}

type BACnetAddressBinding struct {
	DeviceIdentifier ObjectIdentifier
	DeviceAddress    BACnetAddress
}

func (binding *BACnetAddressBinding) Decode(buffer []byte, offset int, apduLen int) int {
	length := 0
	length1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+length)

	// device_identifier
	if tagNumber == byte(BACnetObjectIdentifier) {
		length += length1
		binding.DeviceIdentifier = ObjectIdentifier{}
		length += binding.DeviceIdentifier.Decode(buffer, offset+length, int(lenValue))
	} else {
		return -1
	}

	length1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+length)

	if tagNumber == byte(UnsignedInt) {
		binding.DeviceAddress = BACnetAddress{}
		length += binding.DeviceAddress.Decode(buffer, offset+length, int(lenValue))
	} else {
		return -1
	}

	return length
}

type BACnetHostNPort struct {
	Host *BACnetHostAddress
	Port uint32
}

func (b *BACnetHostNPort) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0

	if !encoding.IsOpeningTagNumber(buffer, offset+leng, 0) {
		return -1, errors.New("Invalid opening tag")
	}
	leng++
	b.Host = &BACnetHostAddress{}
	hostLen, err := b.Host.Decode(buffer, offset+leng, apduLen-leng)
	if err != nil {
		return -1, err
	}
	leng += hostLen
	leng++

	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 1 {
			leng1, b.Port = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number")
		}
	} else {
		return -1, errors.New("Invalid context tag")
	}

	return leng, nil
}

type BACnetHostAddress struct {
	Value interface{}
}

func (b *BACnetHostAddress) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)

	switch tagNumber {
	case byte(Null):
		leng += leng1
		b.Value = nil
	case byte(OctetString):
		leng += leng1
		leng1, octetString := encoding.DecodeOctetString(buffer, offset+leng, int(lenValue))
		b.Value = octetString
		leng += leng1
	case byte(CharacterString):
		leng += leng1
		leng1, characterString := encoding.DecodeCharacterString(buffer, offset+leng, apduLen-leng, int(lenValue))
		b.Value = characterString
		leng += leng1
	default:
		return -1, errors.New("Invalid tag number")
	}

	return leng, nil
}

type BACnetSecurityKeySet struct {
	KeyRevision    uint32
	ActivationTime *DateTime
	ExpirationTime *DateTime
	KeyIDs         []*BACnetKeyIdentifier
}

func (b *BACnetSecurityKeySet) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0

	// key_revision
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 0 {
			leng1, b.KeyRevision = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number")
		}
	} else {
		return -1, errors.New("Invalid context tag")
	}

	// activation_time
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 1) {
		leng++
		b.ActivationTime = &DateTime{}
		leng1 := b.ActivationTime.Decode(buffer, offset+leng)
		leng += leng1
	} else {
		return -1, errors.New("Invalid opening tag for activation_time")
	}

	// expiration_time
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 2) {
		leng++
		b.ExpirationTime = &DateTime{}
		leng1 := b.ExpirationTime.Decode(buffer, offset+leng)
		leng += leng1
	} else {
		return -1, errors.New("Invalid opening tag for expiration_time")
	}

	b.KeyIDs = make([]*BACnetKeyIdentifier, 0)
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 3) && leng < apduLen {
		leng++
		for !encoding.IsClosingTagNumber(buffer, offset+leng, 3) {
			bValue := &BACnetKeyIdentifier{}
			leng1, err := bValue.Decode(buffer, offset+leng, apduLen-leng)
			if err != nil {
				return -1, err
			}
			b.KeyIDs = append(b.KeyIDs, bValue)
			leng += leng1
		}
		leng++
	} else {
		return -1, errors.New("Invalid opening tag for key_ids or unexpected end of data")
	}

	return leng, nil
}

type BACnetKeyIdentifier struct {
	Algorithm uint32
	KeyID     uint32
}

func (b *BACnetKeyIdentifier) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0

	// algorithm
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 0 {
			leng1, b.Algorithm = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number for algorithm")
		}
	} else {
		return -1, errors.New("Invalid context tag for algorithm")
	}

	// key_id
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 1 {
			leng1, b.KeyID = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number for key_id")
		}
	} else {
		return -1, errors.New("Invalid context tag for key_id")
	}

	return leng, nil
}

type BACnetTimeStamp struct {
	Value interface{}
}

func (b *BACnetTimeStamp) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0
	if encoding.IsContextTag(buffer, offset+leng, 2) {
		// BACnetDateTime
		leng1, tagNumber, _ := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 2 {
			b.Value = &DateTime{}
			leng1 := b.Value.(*DateTime).Decode(buffer, offset+leng)
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number for BACnetDateTime")
		}
	} else if encoding.IsContextTag(buffer, offset+leng, 1) {
		// sequence number
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 1 {
			leng1, seqNum := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			b.Value = seqNum
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number for sequence number")
		}
	} else if encoding.IsContextTag(buffer, offset+leng, 0) {
		// time
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		if tagNumber == 0 {
			leng1, bacnetTime := encoding.DecodeBACnetTimeSafe(buffer, offset+leng, int(lenValue))
			b.Value = bacnetTime
			leng += leng1
		} else {
			return -1, errors.New("Invalid tag number for time")
		}
	} else {
		return -1, errors.New("Invalid context tag")
	}

	return leng, nil
}

func (b *BACnetTimeStamp) Encode() []byte {
	// Implement the encoding logic as needed for your specific application.
	return nil
}

func (b *BACnetTimeStamp) EncodeContext(tagNumber encoding.BACnetApplicationTag) []byte {
	tmp := b.Encode()
	return append(encoding.EncodeTag(tagNumber, true, len(tmp)), tmp...)
}

// ReadAccessSpecification represents a BACnet Read Access Specification.
type ReadAccessSpecification struct {
	ObjectIdentifier         ObjectIdentifier
	ListOfPropertyReferences []BACnetPropertyReference
}

// Decode decodes the ReadAccessSpecification from the buffer.
func (ras *ReadAccessSpecification) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0

	// ObjectIdentifier
	ras.ObjectIdentifier = ObjectIdentifier{}
	leng += ras.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)

	// ListOfPropertyReferences
	if buffer[offset+leng] == 0x30 { // Check for opening tag (0x30)
		leng++

		ras.ListOfPropertyReferences = make([]BACnetPropertyReference, 0)

		for apduLen-leng > 1 && buffer[offset+leng] != 0x00 { // Check for closing tag (0x00)
			bValue := BACnetPropertyReference{}
			leng1, err := bValue.Decode(buffer, offset+leng, apduLen-leng)
			if err != nil {
				return -1, err
			}
			leng += leng1

			ras.ListOfPropertyReferences = append(ras.ListOfPropertyReferences, bValue)
		}
	} else {
		return -1, errors.New("Invalid opening tag for ListOfPropertyReferences")
	}

	leng++

	return leng, nil
}

// BACnetPropertyReference represents a BACnet property reference.
type BACnetPropertyReference struct {
	PropertyIdentifier interface{}
	PropertyArrayIndex uint32
}

// Decode decodes the BACnetPropertyReference from the buffer.
func (ref *BACnetPropertyReference) Decode(buffer []byte, offset, apduLen int) (int, error) {
	leng := 0

	// propertyIdentifier
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, ref.PropertyIdentifier = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		leng += leng1
	} else {
		return -1, errors.New("Missing context tag for PropertyIdentifier")
	}

	if leng < apduLen {
		if encoding.IsContextTag(buffer, offset+leng, 1) && !encoding.IsClosingTagNumber(buffer, offset+leng, 1) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, ref.PropertyArrayIndex = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	return leng, nil
}

type BACnetDeviceObjectPropertyReference struct {
	ObjectIdentifier   ObjectIdentifier
	PropertyIdentifier interface{}
	PropertyArrayIndex uint32
	DeviceIdentifier   ObjectIdentifier
}

func (bdopr *BACnetDeviceObjectPropertyReference) Decode(buffer []byte, offset int, apduLen int) (int, error) {
	leng := 0

	// tag 0 objectidentifier
	bdopr.ObjectIdentifier = ObjectIdentifier{}
	leng1 := bdopr.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)
	if leng1 < 0 {
		return -1, errors.New("failed to decode object identifier")
	}
	leng += leng1

	// tag 1 propertyidentifier
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, bdopr.PropertyIdentifier = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		leng += leng1
	} else {
		return -1, errors.New("Missing tag property Identifier")
	}

	if leng < apduLen {
		// tag 2 property-array-index optional
		if encoding.IsContextTag(buffer, offset+leng, 2) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, bdopr.PropertyArrayIndex = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// tag 3 device-identifier optional
		bdopr.DeviceIdentifier = ObjectIdentifier{}
		leng1 := bdopr.DeviceIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 3)
		if leng1 < 0 {
			return -1, errors.New("failed to decode device identifier")
		}
		leng += leng1
	}

	return leng, nil
}

type BACnetDeviceObjectReference struct {
	DeviceIdentifier ObjectIdentifier
	ObjectIdentifier ObjectIdentifier
}

func (bdor *BACnetDeviceObjectReference) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	// tag 0 device-identifier optional
	bdor.DeviceIdentifier = ObjectIdentifier{}
	leng1 := bdor.DeviceIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)
	if leng1 > 0 {
		leng += leng1
	}

	// tag 1 objectidentifier
	bdor.ObjectIdentifier = ObjectIdentifier{}
	leng1 = bdor.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 1)
	if leng1 < 0 {
		return -1
	}
	leng += leng1

	return leng
}

type BACnetObjectPropertyReference struct {
	ObjectIdentifier   ObjectIdentifier
	PropertyIdentifier interface{}
	PropertyArrayIndex uint32
}

func (bopr *BACnetObjectPropertyReference) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	// tag 0 objectidentifier
	bopr.ObjectIdentifier = ObjectIdentifier{}
	leng1 := bopr.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)
	if leng1 < 0 {
		return -1
	}
	leng += leng1

	// tag 1 propertyidentifier
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, bopr.PropertyIdentifier = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		leng += leng1
	} else {
		return -1
	}

	if leng < apduLen {
		// tag 2 property-array-index optional
		if encoding.IsContextTag(buffer, offset+leng, 2) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, bopr.PropertyArrayIndex = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	return leng
}

type BACnetAccumulatorRecord struct {
	Timestamp         BACnetTimeStamp
	PresentValue      uint32
	AccumulatedValue  uint32
	AccumulatorStatus BACnetAccumulatorStatus
}

type BACnetAccumulatorStatus int

const (
	AccumulatorStatusNormal BACnetAccumulatorStatus = iota
	AccumulatorStatusStarting
	AccumulatorStatusRecovered
	AccumulatorStatusAbnormal
	AccumulatorStatusFailed
)

func (bar *BACnetAccumulatorRecord) Decode(buffer []byte, offset int, apduLen int) (int, error) {
	leng := 0

	// 0 timestamp
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		bar.Timestamp = BACnetTimeStamp{}
		leng1, err := bar.Timestamp.Decode(buffer, offset+leng, int(lenValue))
		if err != nil {
			return -1, errors.New("failed to decode timestamp")
		}
	} else {
		return -1, errors.New("Missing tag 0")
	}

	// 1 present-value
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bar.PresentValue = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1, errors.New("Missing tag 1")
	}

	// 2 accumulated-value
	if encoding.IsContextTag(buffer, offset+leng, 2) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bar.AccumulatedValue = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1, errors.New("Missing tag 2")
	}

	// 3 accumulator-status
	if encoding.IsContextTag(buffer, offset+leng, 3) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, statusValue := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		bar.AccumulatorStatus = BACnetAccumulatorStatus(statusValue)
		leng += leng1
	} else {
		return -1, errors.New("Missing tag 3")
	}

	return leng, nil
}

type BACnetActionList struct {
	Action []BACnetActionCommand
}

func (bal *BACnetActionList) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	// SEQUENCE OF BACnetActionCommand
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 0) {
		leng += 1
		bal.Action = make([]BACnetActionCommand, 0)
		for !encoding.IsClosingTagNumber(buffer, offset+leng, 0) {
			bac := BACnetActionCommand{}
			leng1 := bac.Decode(buffer, offset+leng, apduLen-leng)
			if leng1 < 0 {
				return -1
			}
			leng += leng1
			bal.Action = append(bal.Action, bac)
		}
		leng += 1
	}

	return leng
}

type BACnetActionCommand struct {
	DeviceIdentifier   ObjectIdentifier
	ObjectIdentifier   ObjectIdentifier
	PropertyIdentifier interface{}
	PropertyArrayIndex int
	PropertyValue      []BACnetValue
	Priority           int
	PostDelay          int
	QuitOnFailure      bool
	WriteSuccessful    bool
}

func (bac *BACnetActionCommand) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	// 0 device_identifier optional
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		bac.DeviceIdentifier = ObjectIdentifier{}
		leng += bac.DeviceIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)
	}

	// 1 object_identifier
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		bac.ObjectIdentifier = ObjectIdentifier{}
		leng += bac.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 1)
	} else {
		return -1
	}

	// 2 property_identifier
	if encoding.IsContextTag(buffer, offset+leng, 2) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, bac.PropertyIdentifier = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		if leng1 < 0 {
			return -1
		}
		leng += leng1
	} else {
		return -1
	}

	// 3 property_array_index
	if encoding.IsContextTag(buffer, offset+leng, 3) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		bac.PropertyArrayIndex, _ = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	}

	// tag 4 property-value
	if encoding.IsOpeningTagNumber(buffer, offset+leng, 4) {
		leng += 1
		bac.PropertyValue = []BACnetValue{}
		for !encoding.IsClosingTagNumber(buffer, offset+leng, 4) && leng < apduLen {
			bv := BACnetValue{}
			propID := bac.PropertyIdentifier.(encoding.PropertyIdentifier)
			leng1, _ := bv.Decode(buffer, offset+leng, apduLen-leng, &bac.ObjectIdentifier.Type, &propID)
			if leng1 < 0 {
				return -1
			}
			leng += leng1
			bac.PropertyValue = append(bac.PropertyValue, bv)
		}
		if encoding.IsClosingTagNumber(buffer, offset+leng, 4) {
			leng += 1
		} else {
			return -1
		}
	} else {
		return -1
	}

	if leng < apduLen {
		// tag 5 priority optional
		if encoding.IsContextTag(buffer, offset+leng, 5) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			bac.Priority, _ = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// tag 6 post-delay optional
		if encoding.IsContextTag(buffer, offset+leng, 6) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			bac.PostDelay, _ = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// tag 7 quit-on-failure optional
		if encoding.IsContextTag(buffer, offset+leng, 7) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			uVal, _ := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
			bac.QuitOnFailure = uVal > 0
		}
	}

	if leng < apduLen {
		// tag 8 write-successful optional
		if encoding.IsContextTag(buffer, offset+leng, 8) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			uVal, _ := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
			bac.WriteSuccessful = uVal > 0
		}
	}

	return leng
}

type BACnetScale struct {
	Value interface{}
}

func (bs *BACnetScale) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	if encoding.IsContextTag(buffer, offset+leng, 0) {
		// float-scale
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bs.Value = encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else if encoding.IsContextTag(buffer, offset+leng, 1) {
		// integer-scale
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bs.Value = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1
	}

	return leng
}

type BACnetLightingCommand struct {
	Operation     BACnetLightingOperation
	TargetLevel   float32
	RampRate      float32
	StepIncrement float32
	FadeTime      uint32
	Priority      uint32
}

type BACnetLightingOperation uint32

const (
	LightingOperationUnknown BACnetLightingOperation = iota
	LightingOperationOff
	LightingOperationOn
	LightingOperationToggle
	LightingOperationDecrement
	LightingOperationIncrement
)

func (blc *BACnetLightingCommand) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	// operation
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, uVal := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
		blc.Operation = BACnetLightingOperation(uVal)
	} else {
		return -1
	}

	if leng < apduLen {
		// target-level
		if encoding.IsContextTag(buffer, offset+leng, 1) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, blc.TargetLevel = encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// ramp-rate
		if encoding.IsContextTag(buffer, offset+leng, 2) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, blc.RampRate = encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// step-increment
		if encoding.IsContextTag(buffer, offset+leng, 3) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, blc.StepIncrement = encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// fade-time
		if encoding.IsContextTag(buffer, offset+leng, 4) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, blc.FadeTime = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	if leng < apduLen {
		// priority
		if encoding.IsContextTag(buffer, offset+leng, 5) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			leng1, blc.Priority = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
		}
	}

	return leng
}

type BACnetPrescale struct {
	Multiplier   uint32
	ModuloDivide uint32
}

func (bp *BACnetPrescale) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	// multiplier
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bp.Multiplier = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1
	}

	// modulo_divide
	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bp.ModuloDivide = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else {
		return -1
	}

	return leng
}

type BACnetShedLevelChoice int

const (
	BACnetShedLevelChoicePercent BACnetShedLevelChoice = iota
	BACnetShedLevelChoiceLevel
	BACnetShedLevelChoiceAmount
)

type BACnetShedLevel struct {
	Choice BACnetShedLevelChoice
	Value  interface{}
}

func (bsl *BACnetShedLevel) Decode(buffer []byte, offset int, apduLen int) int {
	leng := 0

	if encoding.IsContextTag(buffer, offset+leng, 0) {
		// percent
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bsl.Value = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
		bsl.Choice = BACnetShedLevelChoicePercent
	} else if encoding.IsContextTag(buffer, offset+leng, 1) {
		// level
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bsl.Value = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
		bsl.Choice = BACnetShedLevelChoiceLevel
	} else if encoding.IsContextTag(buffer, offset+leng, 2) {
		// amount
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, bsl.Value = encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
		leng += leng1
		bsl.Choice = BACnetShedLevelChoiceAmount
	} else {
		return -1
	}

	return leng
}

type BACnetLogRecordChoice int

const (
	BACnetLogRecordChoiceLogStatus BACnetLogRecordChoice = iota
	BACnetLogRecordChoiceBooleanValue
	BACnetLogRecordChoiceRealValue
	BACnetLogRecordChoiceEnumeratedValue
	BACnetLogRecordChoiceUnsignedValue
	BACnetLogRecordChoiceIntegerValue
	BACnetLogRecordChoiceBitstringValue
	BACnetLogRecordChoiceNullValue
	BACnetLogRecordChoiceFailure
	BACnetLogRecordChoiceTimeChange
	BACnetLogRecordChoiceAnyValue
)

type BACnetLogRecord struct {
	Timestamp   BACnetTimeStamp
	LogDatum    interface{}
	StatusFlags BACnetStatusFlags
}

func (blr *BACnetLogRecord) Decode(buffer []byte, offset, apduLen int, objType *encoding.ObjectType, propID *encoding.PropertyIdentifier) int {
	leng := 0

	// timestamp
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		blr.Timestamp = BACnetTimeStamp{}
		leng1, err := blr.Timestamp.Decode(buffer, offset+leng, int(lenValue))
		if err != nil {
			return -1
		}
		leng += leng1
	} else {
		return -1
	}

	if encoding.IsContextTag(buffer, offset+leng, 1) {
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1

		switch BACnetLogRecordChoice(tagNumber) {
		case BACnetLogRecordChoiceLogStatus:
			blr.LogDatum = &BACnetLogStatus{}
			leng += blr.LogDatum.(*BACnetLogStatus).Decode(buffer, offset+leng, int(lenValue))
		case BACnetLogRecordChoiceBooleanValue:
			blr.LogDatum = buffer[offset+leng] > 0
			leng++
		case BACnetLogRecordChoiceRealValue:
			leng1, logValue := encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
			leng += leng1
			blr.LogDatum = logValue
		case BACnetLogRecordChoiceEnumeratedValue:
			leng1, logValue := encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, nil)
			leng += leng1
			blr.LogDatum = logValue
		case BACnetLogRecordChoiceUnsignedValue:
			leng1, logValue := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
			leng += leng1
			blr.LogDatum = logValue
		case BACnetLogRecordChoiceIntegerValue:
			leng1, logValue := encoding.DecodeSigned(buffer, offset+leng, int(lenValue))
			leng += leng1
			blr.LogDatum = logValue
		case BACnetLogRecordChoiceBitstringValue:
			blr.LogDatum = &BACnetBitString{}
			leng += blr.LogDatum.(*BACnetBitString).Decode(buffer, offset+leng, int(lenValue))
		case BACnetLogRecordChoiceNullValue:
			blr.LogDatum = nil
			leng++
		case BACnetLogRecordChoiceFailure:
			blr.LogDatum = &BACnetError{}
			leng += blr.LogDatum.(*BACnetError).Decode(buffer, offset+leng, apduLen-leng)
			if encoding.IsClosingTagNumber(buffer, offset+leng, byte(BACnetLogRecordChoiceFailure)) {
				leng++
			} else {
				return -1
			}
		case BACnetLogRecordChoiceTimeChange:
			leng1, logValue := encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
			leng += leng1
			blr.LogDatum = logValue
		case BACnetLogRecordChoiceAnyValue:
			blr.LogDatum = []BACnetValue{}
			for !encoding.IsClosingTagNumber(buffer, offset+leng, byte(BACnetLogRecordChoiceAnyValue)) && leng < apduLen {
				bValue := BACnetValue{}
				leng1, _ := bValue.Decode(buffer, offset+leng, apduLen-leng, objType, propID)
				if leng1 < 0 {
					return -1
				}
				leng += leng1
				blr.LogDatum = append(blr.LogDatum.([]BACnetValue), bValue)
			}
			if encoding.IsClosingTagNumber(buffer, offset+leng, byte(BACnetLogRecordChoiceAnyValue)) {
				leng++
			} else {
				return -1
			}
		default:
			return -1
		}
	} else {
		return -1
	}

	if leng < apduLen {
		// status-flags optional
		if encoding.IsContextTag(buffer, offset+leng, 2) {
			leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
			leng += leng1
			blr.StatusFlags = BACnetStatusFlags{}
			leng += blr.StatusFlags.Decode(buffer, offset+leng, int(lenValue))
		}
	}

	return leng
}

type BACnetLogStatus struct {
	UnusedBits uint8
	BitString  *BACnetBitString
}

func NewBACnetLogStatus() BACnetLogStatus {
	return BACnetLogStatus{
		UnusedBits: 5,
		BitString:  NewBACnetBitString(5, *internal.NewBitArrayFromByte(0x00)),
	}
}

func (bls *BACnetLogStatus) Decode(buffer []byte, offset, apduLen int) int {
	bls.BitString = NewBACnetBitString(5, *internal.NewBitArrayFromByte(0x00))
	return bls.BitString.Decode(buffer, offset, apduLen)
}

func (bls *BACnetLogStatus) SetLogDisabled(a bool) {
	bls.BitString.Value.Set(0, a)
}

func (bls *BACnetLogStatus) SetBufferPurged(a bool) {
	bls.BitString.Value.Set(1, a)
}

func (bls *BACnetLogStatus) SetLogInterrupted(a bool) {
	bls.BitString.Value.Set(2, a)
}

func (bls *BACnetLogStatus) LogDisabled() bool {
	return bls.BitString.Value.Get(0)
}

func (bls *BACnetLogStatus) BufferPurged() bool {
	return bls.BitString.Value.Get(1)
}

func (bls *BACnetLogStatus) LogInterrupted() bool {
	return bls.BitString.Value.Get(2)
}

type BACnetError struct {
	ErrorClass ErrorClassEnum
	ErrorCode  ErrorCodeEnum
}

func (be *BACnetError) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0

	// Decode error_class
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber == byte(Enumerated) {
		leng1, eVal := encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, nil)
		leng += leng1
		be.ErrorClass = ErrorClassEnum(eVal.(uint32))
	} else {
		return -1
	}

	// Decode error_code
	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber == byte(Enumerated) {
		leng1, eVal := encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, nil)
		leng += leng1
		be.ErrorCode = ErrorCodeEnum(eVal.(uint32))
	} else {
		return -1
	}

	return leng
}

type BACnetCalendarEntry struct {
	Value interface{}
}

func (ce *BACnetCalendarEntry) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	leng += leng1
	if tagNumber == 0 {
		leng1, ce.Value = encoding.DecodeDateSafe(buffer, offset+leng, int(lenValue))
		leng += leng1
	} else if tagNumber == 1 {
		ce.Value = &BACnetDateRange{}
		leng1, err := ce.Value.(*BACnetDateRange).Decode(buffer, offset+leng, int(lenValue))
		if err != nil {
			return -1
		}
		leng += leng1
	} else if tagNumber == 2 {
		ce.Value = &BACnetWeekNDay{}
		leng += ce.Value.(*BACnetWeekNDay).Decode(buffer, offset+leng, int(lenValue))
	} else {
		return -1
	}

	return leng
}

type BACnetEventLogRecord struct {
	Timestamp DateTime
	LogDatum  interface{}
}

func (elr *BACnetEventLogRecord) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	if encoding.IsContextTag(buffer, offset+leng, 0) {
		leng1, _, _ := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		elr.Timestamp = DateTime{}
		leng += elr.Timestamp.Decode(buffer, offset+leng)
	} else {
		return -1
	}

	return leng
}

type BACnetWeekNDay struct {
	Month       int
	WeekOfMonth int
	DayOfWeek   int
}

func (wnd *BACnetWeekNDay) Decode(buffer []byte, offset, apduLen int) int {
	if apduLen >= 3 {
		wnd.Month = int(buffer[offset])
		wnd.WeekOfMonth = int(buffer[offset+1])
		wnd.DayOfWeek = int(buffer[offset+2])
	} else {
		return -1
	}
	return 3
}

type ReadAccessResultReadResult struct {
	PropertyIdentifier encoding.PropertyIdentifier
	PropertyArrayIndex uint32
	ReadResult         interface{} // Either BACnetValue or BACnetError
}

func (rarr *ReadAccessResultReadResult) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	// 2 propertyidentifier
	if encoding.IsContextTag(buffer, offset+leng, 2) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		propID := encoding.PropertyList
		leng1, propertyIdentifier := encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, &propID)
		leng += leng1
		rarr.PropertyIdentifier = encoding.PropertyIdentifier(propertyIdentifier.(uint32))
	} else {
		return -1
	}

	// 3 property_array_index
	if encoding.IsContextTag(buffer, offset+leng, 3) {
		leng1, _, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1
		leng1, propertyArrayIndex := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		leng += leng1
		rarr.PropertyArrayIndex = propertyArrayIndex
	}

	if leng < apduLen {
		if encoding.IsOpeningTagNumber(buffer, offset+leng, 4) {
			rarr.ReadResult = &BACnetValue{}
			leng1, err := rarr.ReadResult.(*BACnetValue).Decode(buffer, offset+leng, apduLen-leng, nil, nil)
			if err != nil {
				return -1
			}
			leng += leng1
			if encoding.IsClosingTagNumber(buffer, offset+leng, 4) {
				leng += 1
			} else {
				return -1
			}
		} else if encoding.IsOpeningTagNumber(buffer, offset+leng, 5) {
			rarr.ReadResult = &BACnetError{}
			leng += rarr.ReadResult.(*BACnetError).Decode(buffer, offset+leng, apduLen-leng)
			if encoding.IsClosingTagNumber(buffer, offset+leng, 5) {
				leng += 1
			} else {
				return -1
			}
		}
	}
	return leng
}

type ReadAccessResult struct {
	ObjectIdentifier ObjectIdentifier
	ListOfResults    []ReadAccessResultReadResult
}

func (rar *ReadAccessResult) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	// tag 0 objectidentifier
	rar.ObjectIdentifier = ObjectIdentifier{}
	if encoding.IsClosingTagNumber(buffer, offset+leng, 0) {
		leng += rar.ObjectIdentifier.DecodeContext(buffer, offset+leng, apduLen-leng, 0)
	} else {
		return -1
	}

	if encoding.IsOpeningTagNumber(buffer, offset+leng, 1) {
		leng += 1
		rar.ListOfResults = make([]ReadAccessResultReadResult, 0)

		for (apduLen-leng) > 1 && !encoding.IsClosingTagNumber(buffer, offset+leng, 1) {
			bValue := ReadAccessResultReadResult{}
			leng += bValue.Decode(buffer, offset+leng, apduLen-leng)

			rar.ListOfResults = append(rar.ListOfResults, bValue)
		}

		if encoding.IsClosingTagNumber(buffer, offset+leng, 1) {
			leng += 1
		} else {
			return -1
		}
	} else {
		return -1
	}

	return leng
}

type BACnetAccessRule struct {
	TimeRangeSpecifier BACnetTimeRangeSpecifierChoice
	TimeRange          BACnetDeviceObjectPropertyReference
	LocationSpecifier  BACnetLocationSpecifierChoice
	Location           BACnetDeviceObjectReference
	Enable             bool
}

type BACnetTimeRangeSpecifierChoice int

const (
	Specified BACnetTimeRangeSpecifierChoice = iota
	Always
)

type BACnetLocationSpecifierChoice int

const (
	SpecifiedLocation BACnetLocationSpecifierChoice = iota
	All
)

func (bar *BACnetAccessRule) Decode(buffer []byte, offset, apduLen int) int {
	return -1
}

type BACnetNameValue struct {
	Name  string
	Value BACnetValue
}

func (bnv *BACnetNameValue) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0

	// Name
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != 0 {
		return -1
	}
	leng += leng1
	leng1, bnv.Name = encoding.DecodeCharacterString(buffer, offset+leng, apduLen-leng, int(lenValue))
	leng += leng1

	// Decode value
	decodeLen := 0
	if leng < apduLen {
		leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
		leng += leng1

		switch ApplicationTags(tagNumber) {
		case Null:
			bnv.Value = BACnetValue{Value: nil}
			decodeLen = 0
			// Fixme: fix null type nothing else to do, some Error occurs!!!!
		case Boolean:
			if lenValue > 0 {
				bnv.Value = BACnetValue{Value: true}
			} else {
				bnv.Value = BACnetValue{Value: false}
			}
		case UnsignedInt:
			decodeLen, bnv.Value.Value = encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
		case SignedInt:
			decodeLen, bnv.Value.Value = encoding.DecodeSigned(buffer, offset+leng, int(lenValue))
		case Real:
			decodeLen, bnv.Value.Value = encoding.DecodeRealSafe(buffer, offset+leng, int(lenValue))
		case Double:
			decodeLen, bnv.Value.Value = encoding.DecodeDoubleSafe(buffer, offset+leng, int(lenValue))
		case OctetString:
			decodeLen, bnv.Value.Value = encoding.DecodeOctetString(buffer, offset+leng, int(lenValue))
		case CharacterString:
			decodeLen, bnv.Value.Value = encoding.DecodeCharacterString(buffer, offset+leng, apduLen-leng, int(lenValue))
		case BitString:
			bitValue := BACnetBitString{}
			decodeLen = bitValue.Decode(buffer, offset+leng, int(lenValue))
			bnv.Value.Value = bitValue
		case Enumerated:
			decodeLen, bnv.Value.Value = encoding.DecodeEnumerated(buffer, offset+leng, lenValue, nil, nil)
		case Date:
			decodeLen, dateValue := encoding.DecodeDateSafe(buffer, offset+leng, int(lenValue))

			if leng < apduLen {
				leng1, tagNumber, _ := encoding.DecodeTagNumberAndValue(buffer, offset+leng+decodeLen)
				if tagNumber == byte(Time) {
					leng += leng1
					leng--
					bnv.Value.Value = &DateTime{}
					decodeLen = bnv.Value.Value.(*DateTime).Decode(buffer, offset+leng)
				}
			} else {
				bnv.Value.Value = dateValue
			}
		case Time:
			decodeLen, bnv.Value.Value = encoding.DecodeBACnetTimeSafe(buffer, offset+leng, int(lenValue))
		}

		if decodeLen < 0 {
			return -1
		}
		leng += decodeLen
	}

	return leng
}

type BACnetNameValueCollection struct {
	Members []BACnetNameValue
}

func (bnc *BACnetNameValueCollection) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0

	// Check if it's an opening tag number
	if !encoding.IsOpeningTagNumber(buffer, offset+leng, 0) {
		return -1
	}

	leng += 1
	bnc.Members = make([]BACnetNameValue, 0)

	for !encoding.IsClosingTagNumber(buffer, offset+leng, 0) {
		bValue := BACnetNameValue{}
		leng1 := bValue.Decode(buffer, offset+leng, apduLen-leng)
		if leng1 < 0 {
			return -1
		}
		leng += leng1
		bnc.Members = append(bnc.Members, bValue)
	}

	leng += 1
	return leng
}

type BACnetSecurityPolicy int

type BACnetNetworkSecurityPolicy struct {
	PortID        int
	SecurityLevel BACnetSecurityPolicy
}

func (bns *BACnetNetworkSecurityPolicy) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0

	// port_id
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != 0 {
		return -1
	}
	leng += leng1
	leng1, portID := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
	leng += leng1
	bns.PortID = int(portID)

	leng = 0
	// security_level
	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != 1 {
		return -1
	}
	leng += leng1
	leng1, uVal := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
	leng += leng1
	bns.SecurityLevel = BACnetSecurityPolicy(uVal)

	return leng
}

type BACnetPortPermission struct {
	PortID  int
	Enabled bool
}

func (bpp *BACnetPortPermission) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0

	// port_id
	leng1, tagNumber, lenValue := encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != 0 {
		return -1
	}
	leng += leng1
	leng1, portID := encoding.DecodeUnsigned(buffer, offset+leng, int(lenValue))
	leng += leng1
	bpp.PortID = int(portID)

	leng = 0
	// enabled
	leng1, tagNumber, lenValue = encoding.DecodeTagNumberAndValue(buffer, offset+leng)
	if tagNumber != 1 {
		return -1
	}
	leng += leng1
	if lenValue > 0 {
		bpp.Enabled = true
	} else {
		bpp.Enabled = false
	}

	return leng
}

type BACnetPriorityValue struct {
	Value interface{}
}

func (bpv *BACnetPriorityValue) Decode(buffer []byte, offset, apduLen int) int {
	// TODO Implement decoding logic for BACnetPriorityValue
	return -1
}

type BACnetPriorityArray struct {
	Value [16]BACnetPriorityValue
}

func (bpa *BACnetPriorityArray) Decode(buffer []byte, offset, apduLen int) int {
	leng := 0
	i := 0

	for leng < apduLen && i < 16 {
		bpa.Value[i] = BACnetPriorityValue{}
		leng += bpa.Value[i].Decode(buffer, offset+leng, apduLen-leng)
		i++
	}

	return leng
}

type BACnetProcessIdSelection struct {
	Value interface{} // You can specify the type you expect here
}

func (bps *BACnetProcessIdSelection) Decode(buffer []byte, offset, apduLen int) int {
	// TODO Implement decoding logic for BACnetProcessIdSelection
	return -1
}

type BACnetPropertyAccessResult struct {
	ObjectIdentifier   ObjectIdentifier
	PropertyIdentifier encoding.PropertyIdentifier
	PropertyArrayIndex int
	DeviceIdentifier   ObjectIdentifier
	AccessResult       interface{}
}

func (bpar *BACnetPropertyAccessResult) Decode(buffer []byte, offset, apduLen int) int {
	// TODO Implement decoding logic for BACnetPropertyAccessResult here
	return -1
}

type BACnetSetpointReference struct {
	Value interface{}
}

func (bsr *BACnetSetpointReference) Decode(buffer []byte, offset, apduLen int) int {
	// TODO Implement decoding logic for BACnetSetpointReference here
	return 0
}

type BACnetSpecialEvent struct {
	Period           interface{}
	ListOfTimeValues []interface{}
	EventPriority    int
}

func (bse *BACnetSpecialEvent) Decode(buffer []byte, offset, apduLen int) int {
	// TODO Implement decoding logic for BACnetSpecialEvent here
	return 0
}

type BACnetTimerStateChangeValue struct {
	Value interface{}
}

func (scv *BACnetTimerStateChangeValue) Decode([]byte, int, int) int {
	// TODO implement decoder
	return -1
}

type BACnetValueSource struct {
	Value interface{}
}

func (scv *BACnetValueSource) Decode([]byte, int, int) int {
	// TODO implement decoder
	return -1
}

type BACnetVMACEntry struct {
	VirtualMacAddress interface{}
	NativeMacAddress  interface{}
}

func (scv *BACnetVMACEntry) Decode([]byte, int, int) int {
	// TODO implement decoder
	return -1
}

type BACnetAssignedAccessRights struct {
	AssignedAccessRights BACnetDeviceObjectReference
	Enable               bool
}

func (scv *BACnetAssignedAccessRights) Decode([]byte, int, int) int {
	// TODO implement decoder
	return -1
}

type BACnetAssignedLandingCalls struct {
	LandingCalls []landingCall
}

type landingCall struct {
	FloorNumber int
	Direction   BACnetLiftCarDirection
}

func (balc *BACnetAssignedLandingCalls) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetAssignedLandingCalls
	return 0
}

type BACnetLiftCarDirection int

type BACnetAuthenticationFactor struct {
	FormatType  BACnetAuthenticationFactorType
	FormatClass int
	Value       []byte
}

func (baf *BACnetAuthenticationFactor) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetAuthenticationFactor
	return 0
}

type BACnetAuthenticationFactorType int

type BACnetAuthenticationFactorFormat struct {
	FormatType   BACnetAuthenticationFactorType
	VendorID     int
	VendorFormat int
}

func (baff *BACnetAuthenticationFactorFormat) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetAuthenticationFactorFormat
	return 0
}

type BACnetAuthenticationPolicy struct {
	Policies      []policy
	OrderEnforced bool
	Timeout       int
}

type policy struct {
	CredentialDataInput BACnetDeviceObjectReference
	Index               int
}

func (bap *BACnetAuthenticationPolicy) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetAuthenticationPolicy
	return 0
}

type BACnetBDTEntry struct {
	// Define BACnetBDTEntry structure here
}

type BACnetChannelValue struct {
	Value interface{}
}

func (bcv *BACnetChannelValue) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetChannelValue
	return 0
}

type BACnetCOVSubscription struct {
	Recipient                   BACnetRecipientProcess
	MonitoredPropertyReference  BACnetObjectPropertyReference
	IssueConfirmedNotifications bool
	TimeRemaining               int
	COVIncrement                float64
}

func (bcs *BACnetCOVSubscription) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetCOVSubscription
	return 0
}

type BACnetAccessAuthenticationFactorDisable int

type BACnetCredentialAuthenticationFactor struct {
	Disable              BACnetAccessAuthenticationFactorDisable
	AuthenticationFactor BACnetAuthenticationFactor
}

func (bcaf *BACnetCredentialAuthenticationFactor) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetCredentialAuthenticationFactor
	return 0
}

type BACnetDailySchedule struct {
	DaySchedule []interface{}
}

func (bds *BACnetDailySchedule) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetDailySchedule
	return 0
}

type BACnetRecipientProcess struct {
	// Define BACnetRecipientProcess structure here
}

type BACnetEventNotificationSubscription struct {
	Recipient                   BACnetRecipient
	ProcessIdentifier           int
	IssueConfirmedNotifications bool
	TimeRemaining               int
}

func (bens *BACnetEventNotificationSubscription) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetEventNotificationSubscription
	return 0
}

type BACnetEventParameter struct {
	Value interface{}
}

func (bep *BACnetEventParameter) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetEventParameter
	return 0
}

type BACnetFaultParameter struct {
	Value interface{}
}

func (bfp *BACnetFaultParameter) Decode(buffer []byte, offset, apduLen int) int {
	// Implement decoding logic for BACnetFaultParameter
	return 0
}
