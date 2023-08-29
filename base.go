package bacnet

type NetworkPriority int

const (
	LifeSafetyMessage NetworkPriority = iota + 1
	CriticalEquipmentMessage
	UrgentMessage
	NormalMessage
)

type NetworkLayerMessageType int

const (
	WhoIsRouterToNetwork NetworkLayerMessageType = iota
	IAmRouterToNetwork
	ICouldBeRouterToNetwork
	RejectMessageToNetwork
	RouterBusyToNetwork
	RouterAvailableToNetwork
	InitRtTable
	InitRtTableAck
	EstablishConnectionToNetwork
	DisconnectConnectionToNetwork
	ChallengeRequest
	SecurityPayload
	SecurityResponse
	RequestKeyUpdate
	UpdateKeySet
	UpdateDistributionKey
	RequestMasterKey
	SetMasterKey
	WhatIsNetworkNumber
	NetworkNumberIs
)

type BacnetMaxSegments int

const (
	MaxSEG0  BacnetMaxSegments = 0
	MaxSEG2  BacnetMaxSegments = 0x10
	MaxSEG4  BacnetMaxSegments = 0x20
	MaxSEG8  BacnetMaxSegments = 0x30
	MaxSEG16 BacnetMaxSegments = 0x40
	MaxSEG32 BacnetMaxSegments = 0x50
	MaxSEG64 BacnetMaxSegments = 0x60
	MaxSEG65 BacnetMaxSegments = 0x70
)

type BacnetMaxAdpu int

const (
	MaxAPDU50 BacnetMaxAdpu = iota
	MaxAPDU128
	MaxAPDU206
	MaxAPDU480
	MaxAPDU1024
	MaxAPDU1476
)

type BacnetPduTypes int

const (
	PDUTypeConfirmedServiceRequest BacnetPduTypes = iota
	Server
	NegativeAck
	// TODO
	SegmentResponseAccepted
	MORE_FOLLOWS
	SEGMENTED_MESSAGE                BacnetPduTypes = 8
	PDUTypeUnconfirmedServiceRequest BacnetPduTypes = 0x10
	PDUTypeSimpleAck                 BacnetPduTypes = 0x20
	PDUTypeComplexAck                BacnetPduTypes = 0x30
	PDUTypeSegmentAck                BacnetPduTypes = 0x40
	PDUTypeError                     BacnetPduTypes = 0x50
	PDUTypeReject                    BacnetPduTypes = 0x60
	PDUTypeAbort                     BacnetPduTypes = 0x70
	PDUTypeMask                      BacnetPduTypes = 0xF0
)

type BacnetCharacterStringEncodings int

const (
	CharacterANSIX34  BacnetCharacterStringEncodings = 0
	CharacterUTF8     BacnetCharacterStringEncodings = 0
	CharacterMSDBCS   BacnetCharacterStringEncodings = 1
	CharacterJISC6226 BacnetCharacterStringEncodings = 2
	CharacterJISX0208 BacnetCharacterStringEncodings = 2
	CharacterUCS4     BacnetCharacterStringEncodings = 3
	CharacterUCS2     BacnetCharacterStringEncodings = 4
	CharacterISO8859  BacnetCharacterStringEncodings = 5
)

type BACnetApplicationTag int

const (
	Null BACnetApplicationTag = iota
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

type BacnetNpduControl int

const (
	PriorityNormalMessage BacnetNpduControl = iota
	PriorityUrgentMessage
	PriorityCriticalMessage
	PriorityLifeSafetyMessage
	ExpectingReply
	SourceSpecified      BacnetNpduControl = 8
	DestinationSpecified BacnetNpduControl = 32
	NetworkLayerMessage  BacnetNpduControl = 128
)

type BacnetNetworkMessageType int

const (
	NetworkMessageWhoIsRouterToNetwork BacnetNetworkMessageType = iota
	NetworkMessageIAmRouterToNetwork
	NetworkMessageICouldBeRouterToNetwork
	NetworkMessageRejectMessageToNetwork
	NetworkMessageRouterBusyToNetwork
	NetworkMessageRouterAvailableToNetwork
	NetworkMessageInitRtTable
	NetworkMessageInitRtTableAck
	NetworkMessageEstablishConnectionToNetwork
	NetworkMessageDisconnectConnectionToNetwork
	NetworkMessageChallengeRequest
	NetworkMessageSecurityPayload
	NetworkMessageSecurityResponse
	NetworkMessageRequestKeyUpdate
	NetworkMessageUpdateKeySet
	NetworkMessageUpdateDistributionKey
	NetworkMessageRequestMasterKey
	NetworkMessageSetMasterKey
	NetworkMessageWhatIsNetworkNumber
	NetworkMessageNetworkNumberIs
)

// ErrorClassEnum represents the error classes as constants.
type ErrorClassEnum int

const (
	Device ErrorClassEnum = iota
	Object
	Property
	Resources
	Security
	Services
	VT
	Communication
)

// Error Code Enum represents the error codes as constants.
type ErrorCodeEnum int

const (
	Other ErrorCodeEnum = iota
	AuthenticationFailed
	ConfigurationInProgress
	DeviceBusy
	DynamicCreationNotSupported
	FileAccessDenied
	IncompatibleSecurityLevels
	InconsistentParameters
	InconsistentSelectionCriterion
	InvalidDataType
	InvalidFileAccessMethod
	InvalidFileStartPosition
	InvalidOperatorName
	InvalidParameterDataType
	InvalidTimestamp
	KeyGenerationError
	MissingRequiredParameter
	NoObjectsOfSpecifiedType
	NoSpaceForObject
	NoSpaceToAddListElement
	NoSpaceToWriteProperty
	NoVTSessionsAvailable
	PropertyIsNotAList
	ObjectDeletionNotPermitted
	ObjectIdentifierAlreadyExists
	OperationalProblem
	PasswordFailure
	ReadAccessDenied
	SecurityNotSupported
	ServiceRequestDenied
	Timeout
	UnknownObject
	UnknownProperty
	UnknownVTClass
	UnknownVTSession
	UnsupportedObjectType
	ValueOutOfRange
	VTSessionAlreadyClosed
	VTSessionTerminationFailure
	WriteAccessDenied
	CharacterSetNotSupported
	InvalidArrayIndex
	COVSubscriptionFailed
	NotCOVProperty
	OptionalFunctionalityNotSupported
	InvalidConfigurationData
	DataTypeNotSupported
	DuplicateName
	DuplicateObjectID
	PropertyIsNotAnArray
	AbortBufferOverflow
	AbortInvalidAPDUInThisState
	AbortPreemptedbyHigherPriorityTask
	AbortSegmentationNotSupported
	AbortProprietary
	AbortOther
	InvalidTag
	NetworkDown
	RejectBufferOverflow
	RejectInconsistentParameters
	RejectInvalidParameterDataType
	RejectInvalidTag
	RejectMissingRequiredParameter
	RejectParameterOutOfRange
	RejectTooManyArguments
	RejectUndefinedEnumeration
	RejectUnrecognizedService
	RejectProprietary
	RejectOther
	UnknownDevice
	UnknownRoute
	ValueNotInitialized
	InvalidEventState
	NoAlarmConfigured
	LogBufferFull
	LoggedValuePurged
	NoPropertySpecified
	NotConfiguredForTriggeredLogging
	UnknownSubscription
	ParameterOutOfRange
	ListElementNotFound
	Busy
	CommunicationDisabled
	Success
	AccessDenied
	BadDestinationAddress
	BadDestinationDeviceID
	BadSignature
	BadSourceAddress
	BadTimestamp
	CannotUseKey
	CannotVerifyMessageID
	CorrectKeyRevision
	DestinationDeviceIDRequired
	DuplicateMessage
	EncryptionNotConfigured
	EncryptionRequired
	IncorrectKey
	InvalidKeyData
	KeyUpdateInProgress
	MalformedMessage
	NotKeyServer
	SecurityNotConfigured
	SourceSecurityRequired
	TooManyKeys
	UnknownAuthenticationType
	UnknownKey
	UnknownKeyRevision
	UnknownSourceMessage
	NotRouterToDNET
	RouterBusy
	UnknownNetworkMessage
	MessageTooLong
	SecurityError
	AddressingError
	WriteBDTFailed
	ReadBDTFailed
	RegisterForeignDeviceFailed
	ReadFDTFailed
	DeleteFDTEntryFailed
	DistributeBroadcastFailed
	UnknownFileSize
	AbortAPDUTooLong
	AbortApplicationExceededReplyTime
	AbortOutOfResources
	AbortTSMTimeout
	AbortWindowSizeOutOfRange
	FileFull
	InconsistentConfiguration
	InconsistentObjectType
	InternalError
	NotConfigured
	OutOfMemory
	ValueTooLong
	AbortInsufficientSecurity
	AbortSecurityError
	DuplicateEntry
	InvalidValueInThisState
)

type ObjectIdentifier struct {
	Type     ObjectType
	Instance int
}

func (oi *ObjectIdentifier) ASN1decode() {
}
