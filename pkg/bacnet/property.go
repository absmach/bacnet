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
			leng1, err := bValue.Decode(buffer, offset+leng, apduLen-leng, r.ObjectIdentifier.Type, propId)
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

func (bv *BACnetValue) Decode(buffer []byte, offset, apduLen int, objType encoding.ObjectType, propID encoding.PropertyIdentifier) (int, error) {
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
				if propID == encoding.RoutingTable {
					bv.Tag = nil
					bv.Value = &RouterEntry{}
					length--
					decodeLen, err = bv.Value.(*RouterEntry).Decode(buffer, offset+length, apduLen)
					if err != nil {
						return -1, err
					}
				} else if propID == encoding.ActiveVtSessions {
					bv.Tag = nil
					bv.Value = &BACnetVTSession{}
					length--
					decodeLen = bv.Value.(*BACnetVTSession).Decode(buffer, offset+length, apduLen)
				} else if propID == encoding.ThreatLevel || propID == encoding.ThreatAuthority {
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
				switch propID {
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
				decodeLen, bv.Value = encoding.DecodeEnumerated(buffer, offset+length, lenValueType, &objType, &propID)
			case Date:
				switch propID {
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
				if (objType == encoding.DateTimeValue || objType == encoding.TimePatternValue) && (propID == encoding.PresentValue || propID == encoding.RelinquishDefault) {
					decodeLen, bv.Value = encoding.DecodeDateSafe(buffer, offset+length, int(lenValueType))
				}
			case Time:
				decodeLen, bv.Value = encoding.DecodeBACnetTimeSafe(buffer, offset+length, int(lenValueType))
			case BACnetObjectIdentifier:
				if propID == encoding.LastKeyServer ||
					propID == encoding.ManualSlaveAddressBinding ||
					propID == encoding.SlaveAddressBinding ||
					propID == encoding.DeviceAddressBinding {
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
		switch propID {
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
			length += bv.Value.(*ReadAccessSpecification).Decode(buffer, offset+length, apduLen-length)
		case encoding.ListOfObjectPropertyReferences:
			bv.Value = &BACnetDeviceObjectPropertyReference{}
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
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
			bv.Value = NewBACnetDeviceObjectReference()
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case encoding.EventAlgorithmInhibitRef,
			encoding.InputReference,
			encoding.ManipulatedVariableReference,
			encoding.ControlledVariableReference:
			bv.Value = NewBACnetObjectPropertyReference()
			length += bv.Value.(*BACnetObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case encoding.LoggingRecord:
			bv.Value = NewBACnetAccumulatorRecord()
			length += bv.Value.(*BACnetAccumulatorRecord).Decode(buffer, offset+length, apduLen-length)
		case encoding.Action:
			bv.Value = NewBACnetActionList()
			length += bv.Value.(*BACnetActionList).Decode(buffer, offset+length, apduLen-length)
		case encoding.Scale:
			bv.Value = NewBACnetScale()
			length += bv.Value.(*BACnetScale).Decode(buffer, offset+length, apduLen-length)
		case encoding.LightingCommand:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case encoding.Prescale:
			bv.Value = NewBACnetPrescale()
			length += bv.Value.(*BACnetPrescale).Decode(buffer, offset+length, apduLen-length)
		case encoding.RequestedShedLevel,
			encoding.ExpectedShedLevel,
			encoding.ActualShedLevel:
			bv.Value = NewBACnetShedLevel()
			length += bv.Value.(*BACnetShedLevel).Decode(buffer, offset+length, apduLen-length)
		case encoding.LogBuffer:
			if objType == encoding.TrendLog {
				bv.Value = NewBACnetLogRecord()
				length += bv.Value.(*BACnetLogRecord).Decode(buffer, offset+length, apduLen-length)
			} else {
				log.Println("Unhandled context-specific tag:", bv.Tag)
				length = apduLen
			}
		case encoding.DateList:
			bv.Value = NewBACnetCalendarEntry()
			length += bv.Value.(*BACnetCalendarEntry).Decode(buffer, offset+length, apduLen-length)
		case encoding.LogBuffer:
			if objType == encoding.EventLog {
				bv.Value = NewBACnetEventLogRecord()
				length += bv.Value.(*BACnetEventLogRecord).Decode(buffer, offset+length, apduLen-length)
			} else {
				log.Println("Unhandled context-specific tag:", bv.Tag)
				length = apduLen
			}
		case encoding.PresentValue:
			if objType == encoding.Group {
				bv.Value = NewReadAccessResult()
				length += bv.Value.(*ReadAccessResult).Decode(buffer, offset+length, apduLen-length)
			} else {
				log.Println("Unhandled context-specific tag:", bv.Tag)
				length = apduLen
			}
		case encoding.NegativeAccessRules,
			encoding.PositiveAccessRules:
			bv.Value = NewBACnetAccessRule()
			length += bv.Value.(*BACnetAccessRule).Decode(buffer, offset+length, apduLen-length)
		case encoding.Tags:
			bv.Value = NewBACnetNameValue()
			length += bv.Value.(*BACnetNameValue).Decode(buffer, offset+length, apduLen-length)
		case encoding.SubordinateTags:
			bv.Value = NewBACnetNameValueCollection()
			length += bv.Value.(*BACnetNameValueCollection).Decode(buffer, offset+length, apduLen-length)
		case encoding.NetworkAccessSecurityPolicies:
			bv.Value = NewBACnetNetworkSecurityPolicy()
			length += bv.Value.(*BACnetNetworkSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case encoding.PortFilter:
			bv.Value = NewBACnetPortPermission()
			length += bv.Value.(*BACnetPortPermission).Decode(buffer, offset+length, apduLen-length)
		case encoding.PriorityArray:
			bv.Value = NewBACnetPriorityArray()
			length += bv.Value.(*BACnetPriorityArray).Decode(buffer, offset+length, apduLen-length)
		case encoding.ProcessIdentifierFilter:
			bv.Value = NewBACnetProcessIdSelection()
			length += bv.Value.(*BACnetProcessIdSelection).Decode(buffer, offset+length, apduLen-length)
		case encoding.GlobalGroup && propID == encoding.PresentValue:
			bv.Value = NewBACnetPropertyAccessResult()
			length += bv.Value.(*BACnetPropertyAccessResult).Decode(buffer, offset+length, apduLen-length)
		case encoding.SetpointReference:
			bv.Value = NewBACnetSetpointReference()
			length += bv.Value.(*BACnetSetpointReference).Decode(buffer, offset+length, apduLen-length)
		case encoding.ExceptionSchedule:
			bv.Value = NewBACnetSpecialEvent()
			length += bv.Value.(*BACnetSpecialEvent).Decode(buffer, offset+length, apduLen-length)
		case encoding.StateChangeValues:
			bv.Value = NewBACnetTimerStateChangeValue()
			length += bv.Value.(*BACnetTimerStateChangeValue).Decode(buffer, offset+length, apduLen-length)
		case encoding.ValueSource, encoding.ValueSourceArray:
			bv.Value = NewBACnetValueSource()
			length += bv.Value.(*BACnetValueSource).Decode(buffer, offset+length, apduLen-length)
		case encoding.VirtualMacAddressTable:
			bv.Value = NewBACnetVMACEntry()
			length += bv.Value.(*BACnetVMACEntry).Decode(buffer, offset+length, apduLen-length)
		case encoding.AssignedAccessRights:
			bv.Value = NewBACnetAssignedAccessRights()
			length += bv.Value.(*BACnetAssignedAccessRights).Decode(buffer, offset+length, apduLen-length)
		case encoding.AssignedLandingCalls:
			bv.Value = NewBACnetAssignedLandingCalls()
			length += bv.Value.(*BACnetAssignedLandingCalls).Decode(buffer, offset+length, apduLen-length)
		case encoding.AccessEventAuthenticationFactor,
			(objType == encoding.CredentialDataInput && propID == encoding.PresentValue):
			bv.Value = NewBACnetAuthenticationFactor()
			length += bv.Value.(*BACnetAuthenticationFactor).Decode(buffer, offset+length, apduLen-length)
		case encoding.SupportedFormats:
			bv.Value = NewBACnetAuthenticationFactorFormat()
			length += bv.Value.(*BACnetAuthenticationFactorFormat).Decode(buffer, offset+length, apduLen-length)
		case encoding.AuthenticationPolicyList:
			bv.Value = NewBACnetAuthenticationPolicy()
			length += bv.Value.(*BACnetAuthenticationPolicy).Decode(buffer, offset+length, apduLen-length)
		case encoding.Channel && propID == encoding.PresentValue:
			bv.Value = NewBACnetChannelValue()
			length += bv.Value.(*BACnetChannelValue).Decode(buffer, offset+length, apduLen-length)
		case encoding.ActiveCovSubscriptions:
			bv.Value = NewBACnetCOVSubscription()
			length += bv.Value.(*BACnetCOVSubscription).Decode(buffer, offset+length, apduLen-length)
		case encoding.AuthenticationFactors:
			bv.Value = NewBACnetCredentialAuthenticationFactor()
			length += bv.Value.(*BACnetCredentialAuthenticationFactor).Decode(buffer, offset+length, apduLen-length)
		case encoding.WeeklySchedule:
			bv.Value = NewBACnetDailySchedule()
			length += bv.Value.(*BACnetDailySchedule).Decode(buffer, offset+length, apduLen-length)
		case encoding.SubscribedRecipients:
			bv.Value = NewBACnetEventNotificationSubscription()
			length += bv.Value.(*BACnetEventNotificationSubscription).Decode(buffer, offset+length, apduLen-length)
		case encoding.EventParameters:
			bv.Value = NewBACnetEventParameter()
			length += bv.Value.(*BACnetEventParameter).Decode(buffer, offset+length, apduLen-length)
		case encoding.FaultParameters:
			bv.Value = NewBACnetFaultParameter()
			length += bv.Value.(*BACnetFaultParameter).Decode(buffer, offset+length, apduLen-length)
		case encoding.LoggingObject:
			bv.Value = NewBACnetLoggingObject()
			length += bv.Value.(*BACnetLoggingObject).Decode(buffer, offset+length, apduLen-length)
		case encoding.LoggingRecord:
			bv.Value = NewBACnetLoggingRecord()
			length += bv.Value.(*BACnetLoggingRecord).Decode(buffer, offset+length, apduLen-length)
		case encoding.ReinitiateDevice:
			bv.Value = NewBACnetReinitializeDevice()
			length += bv.Value.(*BACnetReinitializeDevice).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierBACNETIPUDPDATAGRAMCONFIGURATION:
			bv.Value = NewBACnetBACnetIPUDPDatagramConfiguration()
			length += bv.Value.(*BACnetBACnetIPUDPDatagramConfiguration).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierREINITIALIZEPARAMETERS:
			bv.Value = NewBACnetReinitializeParameters()
			length += bv.Value.(*BACnetReinitializeParameters).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierDISCONNECTEDONEXCEPTION:
			bv.Value = NewBACnetDisconnect()
			length += bv.Value.(*BACnetDisconnect).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierNOMINALENCYCLE:
			bv.Value = NewBACnetNominalBACnetInterval()
			length += bv.Value.(*BACnetNominalBACnetInterval).Decode(buffer, offset+length, apduLen-length)
		case encoding.NotifyType:
			bv.Value = NewBACnetNotifyType()
			length += bv.Value.(*BACnetNotifyType).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierSUMMATION:
			bv.Value = NewBACnetEventSummation()
			length += bv.Value.(*BACnetEventSummation).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSUSERPASSWORD:
			bv.Value = NewBACnetAccessUserPassword()
			length += bv.Value.(*BACnetAccessUserPassword).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPULSECONFIGURATION:
			bv.Value = NewBACnetPulseConverter()
			length += bv.Value.(*BACnetPulseConverter).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPORTPARAMETERS:
			bv.Value = NewBACnetPortParameters()
			length += bv.Value.(*BACnetPortParameters).Decode(buffer, offset+length, apduLen-length)
		case encoding.TimeDelay,
			BACnetPropertyIdentifierLIGHTCONTROLDELAY,
			BACnetPropertyIdentifierINITIALTIMEDELAY:
			bv.Value = NewBACnetTimeValue()
			length += bv.Value.(*BACnetTimeValue).Decode(buffer, offset+length, apduLen-length)
		case encoding.LightingCommand,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierRADIOFAILUREEVENTS,
			BACnetPropertyIdentifierRADIOFAILUREEVENTS2,
			BACnetPropertyIdentifierMACADDRESSCHANGEEVENTS:
			bv.Value = NewBACnetCOVSubscription()
			length += bv.Value.(*BACnetCOVSubscription).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierSHEDLEVELDESCENDANTS:
			bv.Value = NewBACnetShedLevelDescendants()
			length += bv.Value.(*BACnetShedLevelDescendants).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPERSISTENTDATA:
			bv.Value = NewBACnetScheduleObjectPeriod()
			length += bv.Value.(*BACnetScheduleObjectPeriod).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierRADIOSTATUS,
			BACnetPropertyIdentifierRADIOSTATUS2:
			bv.Value = NewBACnetRadioStatus()
			length += bv.Value.(*BACnetRadioStatus).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierUSERINFORMATION,
			BACnetPropertyIdentifierMACADDRESS:
			bv.Value = NewBACnetMACAddress()
			length += bv.Value.(*BACnetMACAddress).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierCOVMULTIPLESUBSCRIPTIONSFILTER,
			BACnetPropertyIdentifierMONITORMULTIPLEBINARYINPUTS,
			BACnetPropertyIdentifierMONITORMULTIPLEBINARYOUTPUTS,
			BACnetPropertyIdentifierMULTIPLEMONITORING,
			BACnetPropertyIdentifierSTOPWHENFULL,
			BACnetPropertyIdentifierLIMITENABLE,
			BACnetPropertyIdentifierDATAGROUPS,
			BACnetPropertyIdentifierDEVICEADDRESSBINDING:
			bv.Value = NewBACnetMultistateValue()
			length += bv.Value.(*BACnetMultistateValue).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierLIGHTINGDEVICESTATUSALOGGING,
			BACnetPropertyIdentifierLIGHTINGDEVICESTATUSLOGGING,
			BACnetPropertyIdentifierDEVICEADDRESSBINDING,
			BACnetPropertyIdentifierLIGHTINGDEVICEOPERATIONALMODE,
			BACnetPropertyIdentifierLIGHTINGDEVICEOPERATIONALSTATUS,
			BACnetPropertyIdentifierLIGHTINGGROUP,
			BACnetPropertyIdentifierLIGHTINGGRP,
			BACnetPropertyIdentifierLIGHTINGLOGGING:
			bv.Value = NewBACnetLightingGroup()
			length += bv.Value.(*BACnetLightingGroup).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierEVENTTIMESTAMPS:
			bv.Value = NewBACnetTimeStampedValue()
			length += bv.Value.(*BACnetTimeStampedValue).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGGROUP:
			bv.Value = NewBACnetLightingGroup()
			length += bv.Value.(*BACnetLightingGroup).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierNEGATIVEACCESSRULES,
			BACnetPropertyIdentifierPOSITIVEACCESSRULES:
			bv.Value = NewBACnetAccessRule()
			length += bv.Value.(*BACnetAccessRule).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierNETWORKADDRESS,
			BACnetPropertyIdentifierMASTERKEY,
			encoding.AccessUser,
			encoding.AccessZone,
			BACnetPropertyIdentifierAREADELIVERING,
			BACnetPropertyIdentifierAREARELAY,
			BACnetPropertyIdentifierCONTROLLING,
			BACnetPropertyIdentifierDELIVERING,
			BACnetPropertyIdentifierENROLLING,
			BACnetPropertyIdentifierLOWLIMIT,
			BACnetPropertyIdentifierMAXIMUMOUTPUT,
			BACnetPropertyIdentifierMAXIMUMVALUE,
			BACnetPropertyIdentifierMINIMUMOUTPUT,
			BACnetPropertyIdentifierMINIMUMVALUE,
			BACnetPropertyIdentifierEVENTTIME,
			BACnetPropertyIdentifierTIMEDELAY,
			BACnetPropertyIdentifierDURATION,
			BACnetPropertyIdentifierEXCEPTIONALLIMITS,
			BACnetPropertyIdentifierINACTIVESTATE,
			BACnetPropertyIdentifierINSTANTANEOUS,
			BACnetPropertyIdentifierINVALIDATED,
			BACnetPropertyIdentifierLIMITENABLE,
			BACnetPropertyIdentifierRELIABILITY,
			BACnetPropertyIdentifierSCALE,
			BACnetPropertyIdentifierSTEPINCREMENT,
			BACnetPropertyIdentifierTIMER,
			BACnetPropertyIdentifierLIMIT,
			BACnetPropertyIdentifierMAXIMUM,
			BACnetPropertyIdentifierMINIMUM,
			BACnetPropertyIdentifierPULSESCALING,
			BACnetPropertyIdentifierSHUTDOWN,
			BACnetPropertyIdentifierBUFFERPROPERTY,
			BACnetPropertyIdentifierSTREAMINGTHRESHOLDS:
			bv.Value = NewBACnetOctetString()
			length += bv.Value.(*BACnetOctetString).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierCOVMULTIPLESUBSCRIPTIONSFILTER,
			encoding.MultiStateValue:
			bv.Value = NewBACnetMultistateValue()
			length += bv.Value.(*BACnetMultistateValue).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierAUTHENTICATIONFACTORSUPPLIED,
			BACnetPropertyIdentifierAUTHENTICATIONFACTORFORMAT,
			BACnetPropertyIdentifierAUTHENTICATIONPOLICYNAME,
			BACnetPropertyIdentifierAUTHENTICATIONPOLICYNAMES,
			BACnetPropertyIdentifierPOLICYNAMES:
			bv.Value = NewBACnetAuthorization()
			length += bv.Value.(*BACnetAuthorization).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierDEVICEIDENTIFICATION:
			bv.Value = NewBACnetCharacterString()
			length += bv.Value.(*BACnetCharacterString).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierEVENTTIMESTAMPS:
			bv.Value = NewBACnetTimeStampedValue()
			length += bv.Value.(*BACnetTimeStampedValue).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierDEVICEIDENTIFICATION:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierSHEDLEVELS:
			bv.Value = NewBACnetShedLevel()
			length += bv.Value.(*BACnetShedLevel).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetPortFilter()
			length += bv.Value.(*BACnetPortFilter).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPOLICY:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSRULES,
			BACnetPropertyIdentifierINVALIDACTIONS,
			BACnetPropertyIdentifierLOGGINGOBJECT,
			BACnetPropertyIdentifierSAVERESTORESTATE:
			bv.Value = NewBACnetDeviceObjectReference()
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACTIVESEQUENCE,
			BACnetPropertyIdentifierCONTROLSEQUENCEOFOPERATION:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPORTFILTER,
			BACnetPropertyIdentifierAUTHENTICATIONPOLICIES,
			BACnetPropertyIdentifierAUTHENTICATIONPOLICYLIST:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPOLICYPASSWORD,
			BACnetPropertyIdentifierPOLICYTYPE,
			BACnetPropertyIdentifierTIMEDELAY,
			BACnetPropertyIdentifierVERIFYPASSWORD,
			BACnetPropertyIdentifierPORTPARAMETERS,
			BACnetPropertyIdentifierDEVICEADDRESSBINDING:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierRELINQUISHDEFAULT,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSRULES,
			BACnetPropertyIdentifierINVALIDACTIONS,
			BACnetPropertyIdentifierLOGGINGOBJECT,
			BACnetPropertyIdentifierSAVERESTORESTATE:
			bv.Value = NewBACnetDeviceObjectReference()
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSSEQUENCE,
			BACnetPropertyIdentifierACTIVESEQUENCE,
			BACnetPropertyIdentifierCONTROLSEQUENCEOFOPERATION,
			BACnetPropertyIdentifierFEEDINGPIPEINDEX,
			BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE,
			BACnetPropertyIdentifierSTATUSFLAGS:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICY,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPOLICYNAMES,
			BACnetPropertyIdentifierACCESSRULES,
			BACnetPropertyIdentifierLIMITDISABLE,
			BACnetPropertyIdentifierMANUALSLIDERSETTINGS:
			bv.Value = NewBACnetDeviceObjectReference()
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSRULES,
			BACnetPropertyIdentifierINVALIDACTIONS,
			BACnetPropertyIdentifierLOGGINGOBJECT,
			BACnetPropertyIdentifierSAVERESTORESTATE:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPOLICYPASSWORD,
			BACnetPropertyIdentifierPOLICYTYPE,
			BACnetPropertyIdentifierTIMEDELAY,
			BACnetPropertyIdentifierVERIFYPASSWORD:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierCONTROLSEQUENCEOFOPERATION,
			BACnetPropertyIdentifierEXCEPTIONSCHEDULE,
			BACnetPropertyIdentifierEVENTTIMESTAMPS:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierALARMVALUES:
			bv.Value = NewBACnetDeviceObjectReference()
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierALARMVALUES,
			BACnetPropertyIdentifierEVENTTYPE,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierSAFETYPOINTS:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCONTROLMODE:
			bv.Value = NewBACnetLightingControlMode()
			length += bv.Value.(*BACnetLightingControlMode).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierBACNETIPADDRESS,
			BACnetPropertyIdentifierDEFAULTGATEWAY,
			BACnetPropertyIdentifierIPADDRESS,
			BACnetPropertyIdentifierSUBNETMASK:
			bv.Value = NewBACnetIPAddress()
			length += bv.Value.(*BACnetIPAddress).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetPortFilter()
			length += bv.Value.(*BACnetPortFilter).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSRULES:
			bv.Value = NewBACnetDeviceObjectReference()
			length += bv.Value.(*BACnetDeviceObjectReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierRELIABILITY,
			BACnetPropertyIdentifierUNITS:
			bv.Value = NewBACnetReliability()
			length += bv.Value.(*BACnetReliability).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPARAMETERSETUSAGE:
			bv.Value = NewBACnetParameterSetUsage()
			length += bv.Value.(*BACnetParameterSetUsage).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierCONTROLSEQUENCEOFOPERATION,
			BACnetPropertyIdentifierEXCEPTIONSCHEDULE,
			BACnetPropertyIdentifierEXCEPTIONSCHEDULEDEFAULT,
			BACnetPropertyIdentifierLIGHTINGCOMMAND:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGINGDEFAULT,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierEVENTCODE,
			BACnetPropertyIdentifierLONMARKRESOURCE,
			BACnetPropertyIdentifierPOLICIES:
			bv.Value = NewBACnetUnsignedInteger()
			length += bv.Value.(*BACnetUnsignedInteger).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCOMMAND:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierLIGHTINGCONTROLOVERLOADALOGGING,
			BACnetPropertyIdentifierRELOCATELIGHTINGOUTPUTDEVICE:
			bv.Value = NewBACnetLightingCommand()
			length += bv.Value.(*BACnetLightingCommand).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierSAFETYPOINTS:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPOLICYPASSWORD,
			BACnetPropertyIdentifierPOLICYTYPE,
			BACnetPropertyIdentifierTIMEDELAY,
			BACnetPropertyIdentifierVERIFYPASSWORD:
			bv.Value = NewBACnetDeviceObjectPropertyReference()
			length += bv.Value.(*BACnetDeviceObjectPropertyReference).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICY,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierDEVICEIDENTIFICATION:
			bv.Value = NewBACnetCharacterString()
			length += bv.Value.(*BACnetCharacterString).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICY,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case encoding.AccessEvent,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		case BACnetPropertyIdentifierACCESSEVENTS,
			BACnetPropertyIdentifierPOLICIES,
			BACnetPropertyIdentifierPORTFILTER:
			bv.Value = NewBACnetDeviceSecurityPolicy()
			length += bv.Value.(*BACnetDeviceSecurityPolicy).Decode(buffer, offset+length, apduLen-length)
		default:
			bv.Value = nil
		}
	}
	return length, nil
}

func (bv *BACnetValue) Encode() []byte {
	if bv.Tag == nil {
		// Handle NULL case
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
			return encoding.EncodeApplicationBitString(b)
			// Handle BIT_STRING case
			// Add your code here...
		case Enumerated:
			// Handle ENUMERATED case
			// Add your code here...
		case Date:
			// Handle DATE case
			// Add your code here...
		case Time:
			// Handle TIME case
			// Add your code here...
		case BACnetObjectIdentifier:
			// Handle BACNETOBJECTIDENTIFIER case
			// Add your code here...
		default:
			log.Printf("Unsupported BACnetApplicationTag: %v", bv.Tag)
			// Handle other BACnetApplicationTags as needed...
		}
	}

	return nil
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

func (d *BACnetDaysOfWeek) String() string {
	return fmt.Sprintf("%08b", d.bitString.Value)
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
