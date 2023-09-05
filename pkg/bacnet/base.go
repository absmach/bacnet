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

// BACnetPropertyIdentifier represents BACnet property identifiers.
type PropertyIdentifier int

const (
	AckedTransitions                 PropertyIdentifier = 0
	AckRequired                      PropertyIdentifier = 1
	Action                           PropertyIdentifier = 2
	ActionText                       PropertyIdentifier = 3
	ActiveText                       PropertyIdentifier = 4
	ActiveVtSessions                 PropertyIdentifier = 5
	AlarmValue                       PropertyIdentifier = 6
	AlarmValues                      PropertyIdentifier = 7
	All                              PropertyIdentifier = 8
	AllWritesSuccessful              PropertyIdentifier = 9
	ApduSegmentTimeout               PropertyIdentifier = 10
	ApduTimeout                      PropertyIdentifier = 11
	ApplicationSoftwareVersion       PropertyIdentifier = 12
	Archive                          PropertyIdentifier = 13
	Bias                             PropertyIdentifier = 14
	ChangeOfStateCount               PropertyIdentifier = 15
	ChangeOfStateTime                PropertyIdentifier = 16
	NotificationClass                PropertyIdentifier = 17
	Blank1                           PropertyIdentifier = 18
	ControlledVariableReference      PropertyIdentifier = 19
	ControlledVariableUnits          PropertyIdentifier = 20
	ControlledVariableValue          PropertyIdentifier = 21
	CovIncrement                     PropertyIdentifier = 22
	DateList                         PropertyIdentifier = 23
	DaylightSavingsStatus            PropertyIdentifier = 24
	Deadband                         PropertyIdentifier = 25
	DerivativeConstant               PropertyIdentifier = 26
	DerivativeConstantUnits          PropertyIdentifier = 27
	Description                      PropertyIdentifier = 28
	DescriptionOfHalt                PropertyIdentifier = 29
	DeviceAddressBinding             PropertyIdentifier = 30
	DeviceType                       PropertyIdentifier = 31
	EffectivePeriod                  PropertyIdentifier = 32
	ElapsedActiveTime                PropertyIdentifier = 33
	ErrorLimit                       PropertyIdentifier = 34
	EventEnable                      PropertyIdentifier = 35
	EventState                       PropertyIdentifier = 36
	EventType                        PropertyIdentifier = 37
	ExceptionSchedule                PropertyIdentifier = 38
	FaultValues                      PropertyIdentifier = 39
	FeedbackValue                    PropertyIdentifier = 40
	FileAccessMethod                 PropertyIdentifier = 41
	FileSize                         PropertyIdentifier = 42
	FileType                         PropertyIdentifier = 43
	FirmwareRevision                 PropertyIdentifier = 44
	HighLimit                        PropertyIdentifier = 45
	InactiveText                     PropertyIdentifier = 46
	InProcess                        PropertyIdentifier = 47
	InstanceOf                       PropertyIdentifier = 48
	IntegralConstant                 PropertyIdentifier = 49
	IntegralConstantUnits            PropertyIdentifier = 50
	IssueConfirmedNotifications      PropertyIdentifier = 51
	LimitEnable                      PropertyIdentifier = 52
	ListOfGroupMembers               PropertyIdentifier = 53
	ListOfObjectPropertyReferences   PropertyIdentifier = 54
	ListOfSessionKeys                PropertyIdentifier = 55
	LocalDate                        PropertyIdentifier = 56
	LocalTime                        PropertyIdentifier = 57
	Location                         PropertyIdentifier = 58
	LowLimit                         PropertyIdentifier = 59
	ManipulatedVariableReference     PropertyIdentifier = 60
	MaximumOutput                    PropertyIdentifier = 61
	MaxApduLengthAccepted            PropertyIdentifier = 62
	MaxInfoFrames                    PropertyIdentifier = 63
	MaxMaster                        PropertyIdentifier = 64
	MaxPresValue                     PropertyIdentifier = 65
	MinimumOffTime                   PropertyIdentifier = 66
	MinimumOnTime                    PropertyIdentifier = 67
	MinimumOutput                    PropertyIdentifier = 68
	MinPresValue                     PropertyIdentifier = 69
	ModelName                        PropertyIdentifier = 70
	ModificationDate                 PropertyIdentifier = 71
	NotifyType                       PropertyIdentifier = 72
	NumberOfApduRetries              PropertyIdentifier = 73
	NumberOfStates                   PropertyIdentifier = 74
	ObjectIdentifierPI               PropertyIdentifier = 75
	ObjectList                       PropertyIdentifier = 76
	ObjectName                       PropertyIdentifier = 77
	ObjectPropertyReference          PropertyIdentifier = 78
	ObjectTypePI                     PropertyIdentifier = 79
	Optional                         PropertyIdentifier = 80
	OutOfService                     PropertyIdentifier = 81
	OutputUnits                      PropertyIdentifier = 82
	EventParameters                  PropertyIdentifier = 83
	Polarity                         PropertyIdentifier = 84
	PresentValue                     PropertyIdentifier = 85
	Priority                         PropertyIdentifier = 86
	PriorityArray                    PropertyIdentifier = 87
	PriorityForWriting               PropertyIdentifier = 88
	ProcessIdentifier                PropertyIdentifier = 89
	ProgramChange                    PropertyIdentifier = 90
	ProgramLocation                  PropertyIdentifier = 91
	ProgramState                     PropertyIdentifier = 92
	ProportionalConstant             PropertyIdentifier = 93
	ProportionalConstantUnits        PropertyIdentifier = 94
	ProtocolConformanceClass         PropertyIdentifier = 95
	ProtocolObjectTypesSupported     PropertyIdentifier = 96
	ProtocolServicesSupported        PropertyIdentifier = 97
	ProtocolVersion                  PropertyIdentifier = 98
	ReadOnly                         PropertyIdentifier = 99
	ReasonForHalt                    PropertyIdentifier = 100
	Recipient                        PropertyIdentifier = 101
	RecipientList                    PropertyIdentifier = 102
	Reliability                      PropertyIdentifier = 103
	RelinquishDefault                PropertyIdentifier = 104
	Required                         PropertyIdentifier = 105
	Resolution                       PropertyIdentifier = 106
	SegmentationSupported            PropertyIdentifier = 107
	Setpoint                         PropertyIdentifier = 108
	SetpointReference                PropertyIdentifier = 109
	StateText                        PropertyIdentifier = 110
	StatusFlags                      PropertyIdentifier = 111
	SystemStatus                     PropertyIdentifier = 112
	TimeDelay                        PropertyIdentifier = 113
	TimeOfActiveTimeReset            PropertyIdentifier = 114
	TimeOfStateCountReset            PropertyIdentifier = 115
	TimeSynchronizationRecipients    PropertyIdentifier = 116
	Units                            PropertyIdentifier = 117
	UpdateInterval                   PropertyIdentifier = 118
	UtcOffset                        PropertyIdentifier = 119
	VendorIdentifier                 PropertyIdentifier = 120
	VendorName                       PropertyIdentifier = 121
	VtClassesSupported               PropertyIdentifier = 122
	WeeklySchedule                   PropertyIdentifier = 123
	AttemptedSamples                 PropertyIdentifier = 124
	AverageValue                     PropertyIdentifier = 125
	BufferSize                       PropertyIdentifier = 126
	ClientCovIncrement               PropertyIdentifier = 127
	CovResubscriptionInterval        PropertyIdentifier = 128
	CurrentNotifyTime                PropertyIdentifier = 129
	EventTimeStamps                  PropertyIdentifier = 130
	LogBuffer                        PropertyIdentifier = 131
	LogDeviceObjectProperty          PropertyIdentifier = 132
	Enable                           PropertyIdentifier = 133
	LogInterval                      PropertyIdentifier = 134
	MaximumValue                     PropertyIdentifier = 135
	MinimumValue                     PropertyIdentifier = 136
	NotificationThreshold            PropertyIdentifier = 137
	PreviousNotifyTime               PropertyIdentifier = 138
	ProtocolRevision                 PropertyIdentifier = 139
	RecordsSinceNotification         PropertyIdentifier = 140
	RecordCount                      PropertyIdentifier = 141
	StartTime                        PropertyIdentifier = 142
	StopTime                         PropertyIdentifier = 143
	StopWhenFull                     PropertyIdentifier = 144
	TotalRecordCount                 PropertyIdentifier = 145
	ValidSamples                     PropertyIdentifier = 146
	WindowInterval                   PropertyIdentifier = 147
	WindowSamples                    PropertyIdentifier = 148
	MaximumValueTimestamp            PropertyIdentifier = 149
	MinimumValueTimestamp            PropertyIdentifier = 150
	VarianceValue                    PropertyIdentifier = 151
	ActiveCovSubscriptions           PropertyIdentifier = 152
	BackupFailureTimeout             PropertyIdentifier = 153
	ConfigurationFiles               PropertyIdentifier = 154
	DatabaseRevision                 PropertyIdentifier = 155
	DirectReading                    PropertyIdentifier = 156
	LastRestoreTime                  PropertyIdentifier = 157
	MaintenanceRequired              PropertyIdentifier = 158
	MemberOf                         PropertyIdentifier = 159
	Mode                             PropertyIdentifier = 160
	OperationExpected                PropertyIdentifier = 161
	Setting                          PropertyIdentifier = 162
	Silenced                         PropertyIdentifier = 163
	TrackingValue                    PropertyIdentifier = 164
	ZoneMembers                      PropertyIdentifier = 165
	LifeSafetyAlarmValues            PropertyIdentifier = 166
	MaxSegmentsAccepted              PropertyIdentifier = 167
	ProfileName                      PropertyIdentifier = 168
	AutoSlaveDiscovery               PropertyIdentifier = 169
	ManualSlaveAddressBinding        PropertyIdentifier = 170
	SlaveAddressBinding              PropertyIdentifier = 171
	SlaveProxyEnable                 PropertyIdentifier = 172
	LastNotifyRecord                 PropertyIdentifier = 173
	ScheduleDefault                  PropertyIdentifier = 174
	AcceptedModes                    PropertyIdentifier = 175
	AdjustValue                      PropertyIdentifier = 176
	Count                            PropertyIdentifier = 177
	CountBeforeChange                PropertyIdentifier = 178
	CountChangeTime                  PropertyIdentifier = 179
	CovPeriod                        PropertyIdentifier = 180
	InputReference                   PropertyIdentifier = 181
	LimitMonitoringInterval          PropertyIdentifier = 182
	LoggingObject                    PropertyIdentifier = 183
	LoggingRecord                    PropertyIdentifier = 184
	Prescale                         PropertyIdentifier = 185
	PulseRate                        PropertyIdentifier = 186
	Scale                            PropertyIdentifier = 187
	ScaleFactor                      PropertyIdentifier = 188
	UpdateTime                       PropertyIdentifier = 189
	ValueBeforeChange                PropertyIdentifier = 190
	ValueSet                         PropertyIdentifier = 191
	ValueChangeTime                  PropertyIdentifier = 192
	AlignIntervals                   PropertyIdentifier = 193
	IntervalOffset                   PropertyIdentifier = 195
	LastRestartReason                PropertyIdentifier = 196
	LoggingType                      PropertyIdentifier = 197
	RestartNotificationRecipients    PropertyIdentifier = 202
	TimeOfDeviceRestart              PropertyIdentifier = 203
	TimeSynchronizationInterval      PropertyIdentifier = 204
	Trigger                          PropertyIdentifier = 205
	UtcTimeSynchronizationRecipients PropertyIdentifier = 206
	NodeSubtype                      PropertyIdentifier = 207
	NodeType                         PropertyIdentifier = 208
	StructuredObjectList             PropertyIdentifier = 209
	SubordinateAnnotations           PropertyIdentifier = 210
	SubordinateList                  PropertyIdentifier = 211
	ActualShedLevel                  PropertyIdentifier = 212
	DutyWindow                       PropertyIdentifier = 213
	ExpectedShedLevel                PropertyIdentifier = 214
	FullDutyBaseline                 PropertyIdentifier = 215
	RequestedShedLevel               PropertyIdentifier = 218
	ShedDuration                     PropertyIdentifier = 219
	ShedLevelDescriptions            PropertyIdentifier = 220
	ShedLevels                       PropertyIdentifier = 221
	StateDescription                 PropertyIdentifier = 222
	DoorAlarmState                   PropertyIdentifier = 226
	DoorExtendedPulseTime            PropertyIdentifier = 227
	DoorMembers                      PropertyIdentifier = 228
	DoorOpenTooLongTime              PropertyIdentifier = 229
	DoorPulseTime                    PropertyIdentifier = 230
	DoorStatus                       PropertyIdentifier = 231
	DoorUnlockDelayTime              PropertyIdentifier = 232
	LockStatus                       PropertyIdentifier = 233
	MaskedAlarmValues                PropertyIdentifier = 234
	SecuredStatus                    PropertyIdentifier = 235
	AbsenteeLimit                    PropertyIdentifier = 244
	AccessAlarmEvents                PropertyIdentifier = 245
	AccessDoors                      PropertyIdentifier = 246
	AccessEvent                      PropertyIdentifier = 247
	AccessEventAuthenticationFactor  PropertyIdentifier = 248
	AccessEventCredential            PropertyIdentifier = 249
	AccessEventTime                  PropertyIdentifier = 250
	AccessTransactionEvents          PropertyIdentifier = 251
	Accompaniment                    PropertyIdentifier = 252
	AccompanimentTime                PropertyIdentifier = 253
	ActivationTime                   PropertyIdentifier = 254
	ActiveAuthenticationPolicy       PropertyIdentifier = 255
	AssignedAccessRights             PropertyIdentifier = 256
	AuthenticationFactors            PropertyIdentifier = 257
	AuthenticationPolicyList         PropertyIdentifier = 258
	AuthenticationPolicyNames        PropertyIdentifier = 259
	AuthenticationStatus             PropertyIdentifier = 260
	AuthorizationMode                PropertyIdentifier = 261
	BelongsTo                        PropertyIdentifier = 262
	CredentialDisable                PropertyIdentifier = 263
	CredentialStatus                 PropertyIdentifier = 264
	Credentials                      PropertyIdentifier = 265
	CredentialsInZone                PropertyIdentifier = 266
	DaysRemaining                    PropertyIdentifier = 267
	EntryPoints                      PropertyIdentifier = 268
	ExitPoints                       PropertyIdentifier = 269
	ExpiryTime                       PropertyIdentifier = 270
	ExtendedTimeEnable               PropertyIdentifier = 271
	FailedAttemptEvents              PropertyIdentifier = 272
	FailedAttempts                   PropertyIdentifier = 273
	FailedAttemptsTime               PropertyIdentifier = 274
	LastAccessEvent                  PropertyIdentifier = 275
	LastAccessPoint                  PropertyIdentifier = 276
	LastCredentialAdded              PropertyIdentifier = 277
	LastCredentialAddedTime          PropertyIdentifier = 278
	LastCredentialRemoved            PropertyIdentifier = 279
	LastCredentialRemovedTime        PropertyIdentifier = 280
	LastUseTime                      PropertyIdentifier = 281
	Lockout                          PropertyIdentifier = 282
	LockoutRelinquishTime            PropertyIdentifier = 283
	MasterExemption                  PropertyIdentifier = 284
	MaxFailedAttempts                PropertyIdentifier = 285
	Members                          PropertyIdentifier = 286
	MusterPoint                      PropertyIdentifier = 287
	NegativeAccessRules              PropertyIdentifier = 288
	NumberOfAuthenticationPolicies   PropertyIdentifier = 289
	OccupancyCount                   PropertyIdentifier = 290
	OccupancyCountAdjust             PropertyIdentifier = 291
	OccupancyCountEnable             PropertyIdentifier = 292
	OccupancyExemption               PropertyIdentifier = 293
	OccupancyLowerLimit              PropertyIdentifier = 294
	OccupancyLowerLimitEnforced      PropertyIdentifier = 295
	OccupancyState                   PropertyIdentifier = 296
	OccupancyUpperLimit              PropertyIdentifier = 297
	OccupancyUpperLimitEnforced      PropertyIdentifier = 298
	PassbackExemption                PropertyIdentifier = 299
	PassbackMode                     PropertyIdentifier = 300
	PassbackTimeout                  PropertyIdentifier = 301
	PositiveAccessRules              PropertyIdentifier = 302
	ReasonForDisable                 PropertyIdentifier = 303
	SupportedFormats                 PropertyIdentifier = 304
	SupportedFormatClasses           PropertyIdentifier = 305
	ThreatAuthority                  PropertyIdentifier = 306
	ThreatLevel                      PropertyIdentifier = 307
	TraceFlag                        PropertyIdentifier = 308
	TransactionNotificationClass     PropertyIdentifier = 309
	UserExternalIdentifier           PropertyIdentifier = 310
	UserInformationReference         PropertyIdentifier = 311
	UserName                         PropertyIdentifier = 317
	UserType                         PropertyIdentifier = 318
	UsesRemaining                    PropertyIdentifier = 319
	ZoneFrom                         PropertyIdentifier = 320
	ZoneTo                           PropertyIdentifier = 321
	AccessEventTag                   PropertyIdentifier = 322
	GlobalIdentifier                 PropertyIdentifier = 323
	VerificationTime                 PropertyIdentifier = 326
	BaseDeviceSecurityPolicy         PropertyIdentifier = 327
	DistributionKeyRevision          PropertyIdentifier = 328
	DoNotHide                        PropertyIdentifier = 329
	KeySets                          PropertyIdentifier = 330
	LastKeyServer                    PropertyIdentifier = 331
	NetworkAccessSecurityPolicies    PropertyIdentifier = 332
	PacketReorderTime                PropertyIdentifier = 333
	SecurityPduTimeout               PropertyIdentifier = 334
	SecurityTimeWindow               PropertyIdentifier = 335
	SupportedSecurityAlgorithm       PropertyIdentifier = 336
	UpdateKeySetTimeout              PropertyIdentifier = 337
	BackupAndRestoreState            PropertyIdentifier = 338
	BackupPreparationTime            PropertyIdentifier = 339
	RestoreCompletionTime            PropertyIdentifier = 340
	RestorePreparationTime           PropertyIdentifier = 341
	BitMask                          PropertyIdentifier = 342
	BitText                          PropertyIdentifier = 343
	IsUtc                            PropertyIdentifier = 344
	GroupMembers                     PropertyIdentifier = 345
	GroupMemberNames                 PropertyIdentifier = 346
	MemberStatusFlags                PropertyIdentifier = 347
	RequestedUpdateInterval          PropertyIdentifier = 348
	CovuPeriod                       PropertyIdentifier = 349
	CovuRecipients                   PropertyIdentifier = 350
	EventMessageTexts                PropertyIdentifier = 351
	EventMessageTextsConfig          PropertyIdentifier = 352
	EventDetectionEnable             PropertyIdentifier = 353
	EventAlgorithmInhibit            PropertyIdentifier = 354
	EventAlgorithmInhibitRef         PropertyIdentifier = 355
	TimeDelayNormal                  PropertyIdentifier = 356
	ReliabilityEvaluationInhibit     PropertyIdentifier = 357
	FaultParameters                  PropertyIdentifier = 358
	FaultType                        PropertyIdentifier = 359
	LocalForwardingOnly              PropertyIdentifier = 360
	ProcessIdentifierFilter          PropertyIdentifier = 361
	SubscribedRecipients             PropertyIdentifier = 362
	PortFilter                       PropertyIdentifier = 363
	AuthorizationExemptions          PropertyIdentifier = 364
	AllowGroupDelayInhibit           PropertyIdentifier = 365
	ChannelNumber                    PropertyIdentifier = 366
	ControlGroups                    PropertyIdentifier = 367
	ExecutionDelay                   PropertyIdentifier = 368
	LastPriority                     PropertyIdentifier = 369
	WriteStatus                      PropertyIdentifier = 370
	PropertyList                     PropertyIdentifier = 371
	SerialNumber                     PropertyIdentifier = 372
	BlinkWarnEnable                  PropertyIdentifier = 373
	DefaultFadeTime                  PropertyIdentifier = 374
	DefaultRampRate                  PropertyIdentifier = 375
	DefaultStepIncrement             PropertyIdentifier = 376
	EgressTime                       PropertyIdentifier = 377
	InProgress                       PropertyIdentifier = 378
	InstantaneousPower               PropertyIdentifier = 379
	LightingCommand                  PropertyIdentifier = 380
	LightingCommandDefaultPriority   PropertyIdentifier = 381
	MaxActualValue                   PropertyIdentifier = 382
	MinActualValue                   PropertyIdentifier = 383
	Power                            PropertyIdentifier = 384
	Transition                       PropertyIdentifier = 385
	EgressActive                     PropertyIdentifier = 386
	InterfaceValue                   PropertyIdentifier = 387
	FaultHighLimit                   PropertyIdentifier = 388
	FaultLowLimit                    PropertyIdentifier = 389
	LowDiffLimit                     PropertyIdentifier = 390
	StrikeCount                      PropertyIdentifier = 391
	TimeOfStrikeCountReset           PropertyIdentifier = 392
	DefaultTimeout                   PropertyIdentifier = 393
	InitialTimeout                   PropertyIdentifier = 394
	LastStateChange                  PropertyIdentifier = 395
	StateChangeValues                PropertyIdentifier = 396
	TimerRunning                     PropertyIdentifier = 397
	TimerState                       PropertyIdentifier = 398
	ApduLength                       PropertyIdentifier = 399
	IpAddress                        PropertyIdentifier = 400
	IpDefaultGateway                 PropertyIdentifier = 401
	IpDhcpEnable                     PropertyIdentifier = 402
	IpDhcpLeaseTime                  PropertyIdentifier = 403
	IpDhcpLeaseTimeRemaining         PropertyIdentifier = 404
	IpDhcpServer                     PropertyIdentifier = 405
	IpDnsServer                      PropertyIdentifier = 406
	BacnetIpGlobalAddress            PropertyIdentifier = 407
	BacnetIpMode                     PropertyIdentifier = 408
	BacnetIpMulticastAddress         PropertyIdentifier = 409
	BacnetIpNatTraversal             PropertyIdentifier = 410
	IpSubnetMask                     PropertyIdentifier = 411
	BacnetIpUdpPort                  PropertyIdentifier = 412
	BbmdAcceptFdRegistrations        PropertyIdentifier = 413
	BbmdBroadcastDistributionTable   PropertyIdentifier = 414
	BbmdForeignDeviceTable           PropertyIdentifier = 415
	ChangesPending                   PropertyIdentifier = 416
	Command                          PropertyIdentifier = 417
	FdBbmdAddress                    PropertyIdentifier = 418
	FdSubscriptionLifetime           PropertyIdentifier = 419
	LinkSpeed                        PropertyIdentifier = 420
	LinkSpeeds                       PropertyIdentifier = 421
	LinkSpeedAutonegotiate           PropertyIdentifier = 422
	MacAddress                       PropertyIdentifier = 423
	NetworkInterfaceName             PropertyIdentifier = 424
	NetworkNumber                    PropertyIdentifier = 425
	NetworkNumberQuality             PropertyIdentifier = 426
	NetworkType                      PropertyIdentifier = 427
	RoutingTable                     PropertyIdentifier = 428
	VirtualMacAddressTable           PropertyIdentifier = 429
	CommandTimeArray                 PropertyIdentifier = 430
	CurrentCommandPriority           PropertyIdentifier = 431
	LastCommandTime                  PropertyIdentifier = 432
	ValueSource                      PropertyIdentifier = 433
	ValueSourceArray                 PropertyIdentifier = 434
	BacnetIpv6Mode                   PropertyIdentifier = 435
	Ipv6Address                      PropertyIdentifier = 436
	Ipv6PrefixLength                 PropertyIdentifier = 437
	BacnetIpv6UdpPort                PropertyIdentifier = 438
	Ipv6DefaultGateway               PropertyIdentifier = 439
	BacnetIpv6MulticastAddress       PropertyIdentifier = 440
	Ipv6DnsServer                    PropertyIdentifier = 441
	Ipv6AutoAddressingEnable         PropertyIdentifier = 442
	Ipv6DhcpLeaseTime                PropertyIdentifier = 443
	Ipv6DhcpLeaseTimeRemaining       PropertyIdentifier = 444
	Ipv6DhcpServer                   PropertyIdentifier = 445
	Ipv6ZoneIndex                    PropertyIdentifier = 446
	AssignedLandingCalls             PropertyIdentifier = 447
	CarAssignedDirection             PropertyIdentifier = 448
	CarDoorCommand                   PropertyIdentifier = 449
	CarDoorStatus                    PropertyIdentifier = 450
	CarDoorText                      PropertyIdentifier = 451
	CarDoorZone                      PropertyIdentifier = 452
	CarDriveStatus                   PropertyIdentifier = 453
	CarLoad                          PropertyIdentifier = 454
	CarLoadUnits                     PropertyIdentifier = 455
	CarMode                          PropertyIdentifier = 456
	CarMovingDirection               PropertyIdentifier = 457
	CarPosition                      PropertyIdentifier = 458
	ElevatorGroup                    PropertyIdentifier = 459
	EnergyMeter                      PropertyIdentifier = 460
	EnergyMeterRef                   PropertyIdentifier = 461
	EscalatorMode                    PropertyIdentifier = 462
	FloorText                        PropertyIdentifier = 464
	GroupId                          PropertyIdentifier = 465
	GroupMode                        PropertyIdentifier = 467
	HigherDeck                       PropertyIdentifier = 468
	InstallationId                   PropertyIdentifier = 469
	LandingCalls                     PropertyIdentifier = 470
	LandingCallControl               PropertyIdentifier = 471
	LandingDoorStatus                PropertyIdentifier = 472
	LowerDeck                        PropertyIdentifier = 473
	MachineRoomId                    PropertyIdentifier = 474
	MakingCarCall                    PropertyIdentifier = 475
	NextStoppingFloor                PropertyIdentifier = 476
	OperationDirection               PropertyIdentifier = 477
	PassengerAlarm                   PropertyIdentifier = 478
	PowerMode                        PropertyIdentifier = 479
	RegisteredCarCall                PropertyIdentifier = 480
	ActiveCovMultipleSubscriptions   PropertyIdentifier = 481
	ProtocolLevel                    PropertyIdentifier = 482
	ReferencePort                    PropertyIdentifier = 483
	DeployedProfileLocation          PropertyIdentifier = 484
	ProfileLocation                  PropertyIdentifier = 485
	Tags                             PropertyIdentifier = 486
	SubordinateNodeTypes             PropertyIdentifier = 487
	SubordinateRelationships         PropertyIdentifier = 489
	SubordinateTags                  PropertyIdentifier = 488
	DefaultSubordinateRelationship   PropertyIdentifier = 490
	Represents                       PropertyIdentifier = 491
	DefaultPresentValue              PropertyIdentifier = 492
	PresentStage                     PropertyIdentifier = 493
	Stages                           PropertyIdentifier = 494
	StageNames                       PropertyIdentifier = 495
	TargetReferences                 PropertyIdentifier = 496
	FaultSignals                     PropertyIdentifier = 463
)
