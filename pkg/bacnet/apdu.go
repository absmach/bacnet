package bacnet

type BACnetConfirmedServiceChoice int

type BACnetUnconfirmedServiceChoice int

const (
	// Alarm and Event Services
	AcknowledgeAlarm                 BACnetConfirmedServiceChoice = 0
	ConfirmedCovNotification         BACnetConfirmedServiceChoice = 1
	ConfirmedCovNotificationMultiple BACnetConfirmedServiceChoice = 31
	ConfirmedEventNotification       BACnetConfirmedServiceChoice = 2
	GetAlarmSummary                  BACnetConfirmedServiceChoice = 3
	GetEnrollmentSummary             BACnetConfirmedServiceChoice = 4
	GetEventInformation              BACnetConfirmedServiceChoice = 29
	LifeSafetyOperation              BACnetConfirmedServiceChoice = 27
	SubscribeCov                     BACnetConfirmedServiceChoice = 5
	SubscribeCovProperty             BACnetConfirmedServiceChoice = 28
	SubscribeCovPropertyMultiple     BACnetConfirmedServiceChoice = 30
	// File Access Services
	AtomicReadFile  BACnetConfirmedServiceChoice = 6
	AtomicWriteFile BACnetConfirmedServiceChoice = 7
	// Object Access Services
	AddListElement    BACnetConfirmedServiceChoice = 8
	RemoveListElement BACnetConfirmedServiceChoice = 9
	CreateObject      BACnetConfirmedServiceChoice = 10
	DeleteObject      BACnetConfirmedServiceChoice = 11
	ReadProperty      BACnetConfirmedServiceChoice = 12
	// SERVICE_CONFIRMED_READ_CONDITIONAL = 13 removed
	ReadPropertyMultiple  BACnetConfirmedServiceChoice = 14
	ReadRange             BACnetConfirmedServiceChoice = 26
	WriteProperty         BACnetConfirmedServiceChoice = 15
	WritePropertyMultiple BACnetConfirmedServiceChoice = 16
	// Remote Device Management Services
	DeviceCommunicationControl BACnetConfirmedServiceChoice = 17
	ConfirmedPrivateTransfer   BACnetConfirmedServiceChoice = 18
	ConfirmedTextMessage       BACnetConfirmedServiceChoice = 19
	ReinitializeDevice         BACnetConfirmedServiceChoice = 20
	// Virtual Terminal Services
	VTOpen  BACnetConfirmedServiceChoice = 21
	VTClose BACnetConfirmedServiceChoice = 22
	VTData  BACnetConfirmedServiceChoice = 23
	// Security Services
	// SERVICE_CONFIRMED_AUTHENTICATE = 24 removed
	// SERVICE_CONFIRMED_REQUEST_KEY = 25 removed
)

const (
	ServiceChoiceIAm BACnetUnconfirmedServiceChoice = iota
	ServiceChoiceIHave
	UnconfirmedCovNotification
	UnconfirmedEVENTNotification
	UnconfirmedPrivateTransfer
	UnconfirmedTextMessage
	TimeSynchronization
	ServiceChoiceWhoHas
	ServiceChoiceWhoIs
	UTCTimeSynchronization
	WriteGroup
	UnconfirmedCovNotificationMultiple
	ServiceChoiceWhoAmI
	ServiceChoiceYouAre
)

type APDU struct {
	PduType                   BacnetPduTypes
	SegmentedMessage          bool
	MoreFollows               bool
	SegmentedResponseAccepted bool
	MaxSegmentsAccepted       BacnetMaxSegments
	MaxApduLengthAccepted     MaxAPDU
	SequenceNumber            byte
	InvokeID                  byte
	RequenceNumber            byte
	ProposedWindowSize        byte
	ServiceChoice             byte
}

func (a APDU) Encode() []byte {
	buffer := make([]byte, 0)

	tmp := byte(a.PduType)
	if a.SegmentedMessage {
		tmp |= 0x10
	}
	if a.MoreFollows {
		tmp |= 0x20
	}
	if a.SegmentedResponseAccepted {
		tmp |= 0x40
	}
	buffer = append(buffer, tmp)

	if a.PduType == PDUTypeConfirmedServiceRequest {
		buffer = append(buffer, byte(a.MaxSegmentsAccepted)|byte(a.MaxApduLengthAccepted))
		buffer = append(buffer, a.InvokeID)
		if a.SegmentedMessage {
			buffer = append(buffer, a.SequenceNumber, a.ProposedWindowSize)
		}
	} else if a.PduType == PDUTypeUnconfirmedServiceRequest {
		// No additional fields for unconfirmed service request
	} else if a.PduType == PDUTypeSimpleAck {
		buffer = append(buffer, a.InvokeID)
	} else if a.PduType == PDUTypeComplexAck {
		buffer = append(buffer, a.InvokeID)
		if a.SegmentedMessage {
			buffer = append(buffer, a.SequenceNumber, a.ProposedWindowSize)
		}
	} else {
		// Handle other PDU types
	}

	buffer = append(buffer, a.ServiceChoice)
	return buffer
}

func (a *APDU) Decode(buffer []byte, offset int) int {
	length := 0
	a.PduType = BacnetPduTypes(buffer[offset])
	tmp := byte(buffer[offset])
	length++

	if a.PduType == PDUTypeConfirmedServiceRequest {
		a.SegmentedMessage = tmp&0x10 != 0
		a.MoreFollows = tmp&0x20 != 0
		a.SegmentedResponseAccepted = tmp&0x40 != 0
		a.MaxSegmentsAccepted = BacnetMaxSegments(buffer[offset+length] & 0xF0)
		a.MaxApduLengthAccepted = MaxAPDU(buffer[offset+length] & 0x0F)
		length++
		a.InvokeID = buffer[offset+length]
		length++
		if a.SegmentedMessage {
			a.SequenceNumber = buffer[offset+length]
			length++
			a.ProposedWindowSize = buffer[offset+length]
			length++
		}
		a.ServiceChoice = buffer[offset+length]
		length++
	} else if a.PduType == PDUTypeUnconfirmedServiceRequest {
		a.ServiceChoice = buffer[offset+length]
		length++
	} else if a.PduType == PDUTypeSimpleAck {
		a.InvokeID = buffer[offset+length]
		length++
		a.ServiceChoice = buffer[offset+length]
		length++
	} else if a.PduType == PDUTypeComplexAck {
		a.SegmentedMessage = tmp&0x10 != 0
		a.InvokeID = buffer[offset+length]
		length++
		a.ServiceChoice = buffer[offset+length]
		length++
		if a.SegmentedMessage {
			a.SequenceNumber = buffer[offset+length]
			length++
			a.ProposedWindowSize = buffer[offset+length]
			length++
		}
	} else {
		return -1
	}

	return length
}
