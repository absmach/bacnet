package encoding

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

type BACnetSegmentation int

const (
	SEGMENTED_BOTH BACnetSegmentation = iota
	SEGMENTED_TRANSMIT
	SEGMENTED_RECEIVE
	NO_SEGMENTATION
)

type BACnetEventType int

const (
	ChangeOfBitstring          BACnetEventType = 0
	ChangeOfState              BACnetEventType = 1
	ChangeOfValue              BACnetEventType = 2
	CommandFailure             BACnetEventType = 3
	FloatingLimit              BACnetEventType = 4
	OutOfRange                 BACnetEventType = 5
	Complex                    BACnetEventType = 6
	ChangeOfLifeSafety         BACnetEventType = 8
	Extended                   BACnetEventType = 9
	BufferReady                BACnetEventType = 10
	UnsignedRange              BACnetEventType = 11
	BACnetEventTypeAccessEvent BACnetEventType = 13
	DoubleOutOfRange           BACnetEventType = 14
	SignedOutOfRange           BACnetEventType = 15
	UnsignedOutOfRange         BACnetEventType = 16
	ChangeOfCharacterstring    BACnetEventType = 17
	ChangeOfStatusFlag         BACnetEventType = 18
	ChangeOfReliability        BACnetEventType = 19
	None                       BACnetEventType = 20
	ChangeOfDiscreteValue      BACnetEventType = 21
	ChangeOfTimer              BACnetEventType = 22
)

type BACnetFaultType int

const (
	BacnetFaultTypeNone BACnetFaultType = iota
	FaultCHARACTERSTRING
	FaultEXTENDED
	FaultLIFE_SAFETY
	FaultSTATE
	FaultStatusFlags
	FaultOutOfRange
	FaultListed
)

type BACnetNotifyType int

const (
	ALARM BACnetNotifyType = iota
	EVENT
	ACK_NOTIFICATION
)

type BACnetEventState int

const (
	Normal BACnetEventState = iota
	Fault
	OffNormal
	BACnetEventStateHighLimit
	BACnetEventStateLowLimit
	LifeSafetyAlarm
)

type BACnetAccessCredentialDisableReason int

const (
	Disabled BACnetAccessCredentialDisableReason = iota
	DisabledNeedsProvisioning
	DisabledUnassigned
	DisabledNotYetActive
	DisabledExpired
	DisabledLockout
	DisabledMaxDays
	DisabledMaxUses
	DisabledInactivity
	DisabledManual
)

type BACnetAccessCredentialDisable int

const (
	BACnetAccessCredentialDisableNone BACnetAccessCredentialDisable = iota
	Disable
	DisableManual
	DisableLockout
)

type BACnetAccessPassbackMode int

const (
	PassbackOff BACnetAccessPassbackMode = iota
	HardPassback
	SoftPassback
)

type BACnetAccessUserType int

const (
	Asset BACnetAccessUserType = iota
	BACnetAccessUserTypeGroup
	Person
)

type BACnetAccessZoneOccupancyState int

const (
	BACnetAccessZoneOccupancyStateNormal BACnetAccessZoneOccupancyState = iota
	BelowLowerLimit
	AtLowerLimit
	AtUpperLimit
	AboveUpperLimit
	BACnetAccessZoneOccupancyStateDisabled
	NotSupported
)

type BACnetAction int

const (
	Direct BACnetAction = iota
	Reverse
)

type BACnetNetworkNumberQuality int

const (
	Unknown BACnetNetworkNumberQuality = iota
	Learned
	LearnedConfigured
	Configured
)

type BACnetBinaryPV int

const (
	Inactive BACnetBinaryPV = iota
	Active
)

type BACnetDoorValue int

const (
	Lock BACnetDoorValue = iota
	Unlock
	PulseUnlock
	ExtendedPulseUnlock
)

type BACnetAuthenticationStatus int

const (
	NotReady BACnetAuthenticationStatus = iota
	Ready
	BACnetAuthenticationStatusDisabled
	WaitingForAuthenticationFactor
	WaitingForAccompaniment
	WaitingForVerification
	BACnetAuthenticationStatusInProgress
)

type BACnetAuthorizationExemption int

const (
	Passback BACnetAuthorizationExemption = iota
	OccupancyCheck
	BACnetAuthorizationExemptionAccessRights
	BACnetAuthorizationExemptionLockout
	Deny
	Verification
	AuthorizationDelay
)

type BACnetAuthorizationMode int

const (
	Authorize BACnetAuthorizationMode = iota
	GrantActive
	DenyAll
	VerificationRequired
	AuthorizationDelayed
	BACnetAuthorizationModeNone
)

type BACnetBackupState int

const (
	Idle BACnetBackupState = iota
	PreparingForBackup
	PreparingForRestor
	PerformingABACKUP
	PerformingARestor
)

type BACnetBinaryLightingPV int

const (
	Off BACnetBinaryLightingPV = iota
	On
	Warn
	WarnOff
	WarnRelinquish
	Stop
)

type BACnetDeviceStatus int

const (
	Operational BACnetDeviceStatus = iota
	OperationalReadOnly
	DownloadRequired
	DownloadInProgress
	NonOperational
	BackupInProgress
)

type BACnetDoorAlarmState int

const (
	BACnetDoorAlarmStateNormal BACnetDoorAlarmState = iota
	Alarm
	DoorOpenTooLong
	ForcedOpen
	Tamper
	DoorFault
	LockDown
	FreeAccess
	EgressOpen
)

type BACnetDoorSecuredStatus int

const (
	Secured BACnetDoorSecuredStatus = iota
	UNSecured
	BACnetDoorSecuredStatusUnknown
)

type BACnetDoorStatus int

const (
	CLOSED BACnetDoorStatus = iota
	OPENED
	UNKNOWN
	DOOR_FAULT
	UNUSED
	NONE
	CLOSING
	OPENING
	SAFETY_LOCKED
	LIMITED_OPENED
)

type BACnetEngineeringUnits int

const (
	metersPerSecondPerSecond          BACnetEngineeringUnits = 166
	SquareMeters                      BACnetEngineeringUnits = 0
	SquareCentimeters                 BACnetEngineeringUnits = 116
	SquareFeet                        BACnetEngineeringUnits = 1
	SquareInches                      BACnetEngineeringUnits = 115
	Currency1                         BACnetEngineeringUnits = 105
	Currency2                         BACnetEngineeringUnits = 106
	Currency3                         BACnetEngineeringUnits = 107
	Currency4                         BACnetEngineeringUnits = 108
	Currency5                         BACnetEngineeringUnits = 109
	Currency6                         BACnetEngineeringUnits = 110
	Currency7                         BACnetEngineeringUnits = 111
	Currency8                         BACnetEngineeringUnits = 112
	Currency9                         BACnetEngineeringUnits = 113
	Currency10                        BACnetEngineeringUnits = 114
	Milliamperes                      BACnetEngineeringUnits = 2
	Amperes                           BACnetEngineeringUnits = 3
	AmperesPerMeter                   BACnetEngineeringUnits = 167
	AmperesPerSquareMeter             BACnetEngineeringUnits = 168
	AmpereSquareMeters                BACnetEngineeringUnits = 169
	Decibels                          BACnetEngineeringUnits = 199
	DecibelsMillivolt                 BACnetEngineeringUnits = 200
	DecibelsVolt                      BACnetEngineeringUnits = 201
	Farads                            BACnetEngineeringUnits = 170
	Henrys                            BACnetEngineeringUnits = 171
	Ohms                              BACnetEngineeringUnits = 4
	OhmMeters                         BACnetEngineeringUnits = 172
	Milliohms                         BACnetEngineeringUnits = 145
	Kilohms                           BACnetEngineeringUnits = 122
	Megohms                           BACnetEngineeringUnits = 123
	Microsiemens                      BACnetEngineeringUnits = 190
	Millisiemens                      BACnetEngineeringUnits = 202
	Siemens                           BACnetEngineeringUnits = 173
	SiemensPerMeter                   BACnetEngineeringUnits = 174
	Teslas                            BACnetEngineeringUnits = 175
	Volts                             BACnetEngineeringUnits = 5
	Millivolts                        BACnetEngineeringUnits = 124
	Kilovolts                         BACnetEngineeringUnits = 6
	Megavolts                         BACnetEngineeringUnits = 7
	VoltAmperes                       BACnetEngineeringUnits = 8
	KilovoltAmperes                   BACnetEngineeringUnits = 9
	MegavoltAmperes                   BACnetEngineeringUnits = 10
	VoltAmperesReactive               BACnetEngineeringUnits = 11
	KilovoltAmperesReactive           BACnetEngineeringUnits = 12
	MegavoltAmperesReactive           BACnetEngineeringUnits = 13
	VoltsPerDegreeKelvin              BACnetEngineeringUnits = 176
	VoltsPerMeter                     BACnetEngineeringUnits = 177
	DegreesPhase                      BACnetEngineeringUnits = 14
	PowerFactor                       BACnetEngineeringUnits = 15
	Webers                            BACnetEngineeringUnits = 178
	Joules                            BACnetEngineeringUnits = 16
	Kilojoules                        BACnetEngineeringUnits = 17
	KilojoulesPerKilogram             BACnetEngineeringUnits = 125
	Megajoules                        BACnetEngineeringUnits = 126
	WattHours                         BACnetEngineeringUnits = 18
	KilowattHours                     BACnetEngineeringUnits = 19
	MegawattHours                     BACnetEngineeringUnits = 146
	WattHoursReactive                 BACnetEngineeringUnits = 203
	KilowattHoursReactive             BACnetEngineeringUnits = 204
	MegawattHoursReactive             BACnetEngineeringUnits = 205
	Btus                              BACnetEngineeringUnits = 20
	KiloBtus                          BACnetEngineeringUnits = 147
	MegaBtus                          BACnetEngineeringUnits = 148
	Therms                            BACnetEngineeringUnits = 21
	TonHours                          BACnetEngineeringUnits = 22
	JoulesPerKilogramDryAir           BACnetEngineeringUnits = 23
	KilojoulesPerKilogramDryAir       BACnetEngineeringUnits = 149
	MegajoulesPerKilogramDryAir       BACnetEngineeringUnits = 150
	BtusPerPoundDryAir                BACnetEngineeringUnits = 24
	BtusPerPound                      BACnetEngineeringUnits = 117
	JoulesPerDegreeKelvin             BACnetEngineeringUnits = 127
	KilojoulesPerDegreeKelvin         BACnetEngineeringUnits = 151
	MegajoulesPerDegreeKelvin         BACnetEngineeringUnits = 152
	JoulesPerKilogramDegreeKelvin     BACnetEngineeringUnits = 128
	Newton                            BACnetEngineeringUnits = 153
	CyclesPerHour                     BACnetEngineeringUnits = 25
	CyclesPerMinute                   BACnetEngineeringUnits = 26
	Hertz                             BACnetEngineeringUnits = 27
	Kilohertz                         BACnetEngineeringUnits = 129
	Megahertz                         BACnetEngineeringUnits = 130
	PerHour                           BACnetEngineeringUnits = 131
	GramsOfWaterPerKilogramDryAir     BACnetEngineeringUnits = 28
	PercentRelativeHumidity           BACnetEngineeringUnits = 29
	Micrometers                       BACnetEngineeringUnits = 194
	Millimeters                       BACnetEngineeringUnits = 30
	Centimeters                       BACnetEngineeringUnits = 118
	Kilometers                        BACnetEngineeringUnits = 193
	Meters                            BACnetEngineeringUnits = 31
	Inches                            BACnetEngineeringUnits = 32
	Feet                              BACnetEngineeringUnits = 33
	Candelas                          BACnetEngineeringUnits = 179
	CandelasPerSquareMeter            BACnetEngineeringUnits = 180
	WattsPerSquareFoot                BACnetEngineeringUnits = 34
	WattsPerSquareMeter               BACnetEngineeringUnits = 35
	Lumens                            BACnetEngineeringUnits = 36
	Luxes                             BACnetEngineeringUnits = 37
	FootCandles                       BACnetEngineeringUnits = 38
	Milligrams                        BACnetEngineeringUnits = 196
	Grams                             BACnetEngineeringUnits = 195
	Kilograms                         BACnetEngineeringUnits = 39
	PoundsMass                        BACnetEngineeringUnits = 40
	Tons                              BACnetEngineeringUnits = 41
	GramsPerSecond                    BACnetEngineeringUnits = 154
	GramsPerMinute                    BACnetEngineeringUnits = 155
	KilogramsPerSecond                BACnetEngineeringUnits = 42
	KilogramsPerMinute                BACnetEngineeringUnits = 43
	KilogramsPerHour                  BACnetEngineeringUnits = 44
	PoundsMassPerSecond               BACnetEngineeringUnits = 119
	PoundsMassPerMinute               BACnetEngineeringUnits = 45
	PoundsMassPerHour                 BACnetEngineeringUnits = 46
	TonsPerHour                       BACnetEngineeringUnits = 156
	Milliwatts                        BACnetEngineeringUnits = 132
	Watts                             BACnetEngineeringUnits = 47
	Kilowatts                         BACnetEngineeringUnits = 48
	Megawatts                         BACnetEngineeringUnits = 49
	BtusPerHour                       BACnetEngineeringUnits = 50
	KiloBtusPerHour                   BACnetEngineeringUnits = 157
	Horsepower                        BACnetEngineeringUnits = 51
	TonsRefrigeration                 BACnetEngineeringUnits = 52
	Pascals                           BACnetEngineeringUnits = 53
	Hectopascals                      BACnetEngineeringUnits = 133
	Kilopascals                       BACnetEngineeringUnits = 54
	Millibars                         BACnetEngineeringUnits = 134
	Bars                              BACnetEngineeringUnits = 55
	PoundsForcePerSquareInch          BACnetEngineeringUnits = 56
	MillimetersOfWater                BACnetEngineeringUnits = 206
	CentimetersOfWater                BACnetEngineeringUnits = 57
	InchesOfWater                     BACnetEngineeringUnits = 58
	MillimetersOfMercury              BACnetEngineeringUnits = 59
	CentimetersOfMercury              BACnetEngineeringUnits = 60
	InchesOfMercury                   BACnetEngineeringUnits = 61
	DegreesCelsius                    BACnetEngineeringUnits = 62
	DegreesKelvin                     BACnetEngineeringUnits = 63
	DegreesKelvinPerHour              BACnetEngineeringUnits = 181
	DegreesKelvinPerMinute            BACnetEngineeringUnits = 182
	DegreesFahrenheit                 BACnetEngineeringUnits = 64
	DegreeDaysCelsius                 BACnetEngineeringUnits = 65
	DegreeDaysFahrenheit              BACnetEngineeringUnits = 66
	DeltaDegreesFahrenheit            BACnetEngineeringUnits = 120
	DeltaDegreesKelvin                BACnetEngineeringUnits = 121
	Years                             BACnetEngineeringUnits = 67
	Months                            BACnetEngineeringUnits = 68
	Weeks                             BACnetEngineeringUnits = 69
	Days                              BACnetEngineeringUnits = 70
	Hours                             BACnetEngineeringUnits = 71
	Minutes                           BACnetEngineeringUnits = 72
	Seconds                           BACnetEngineeringUnits = 73
	HundredthsSeconds                 BACnetEngineeringUnits = 158
	Milliseconds                      BACnetEngineeringUnits = 159
	NewtonMeters                      BACnetEngineeringUnits = 160
	MillimetersPerSecond              BACnetEngineeringUnits = 161
	MillimetersPerMinute              BACnetEngineeringUnits = 162
	MetersPerSecond                   BACnetEngineeringUnits = 74
	MetersPerMinute                   BACnetEngineeringUnits = 163
	MetersPerHour                     BACnetEngineeringUnits = 164
	KilometersPerHour                 BACnetEngineeringUnits = 75
	FeetPerSecond                     BACnetEngineeringUnits = 76
	FeetPerMinute                     BACnetEngineeringUnits = 77
	MilesPerHour                      BACnetEngineeringUnits = 78
	CubicFeet                         BACnetEngineeringUnits = 79
	CubicMeters                       BACnetEngineeringUnits = 80
	ImperialGallons                   BACnetEngineeringUnits = 81
	Milliliters                       BACnetEngineeringUnits = 197
	Liters                            BACnetEngineeringUnits = 82
	UsGallons                         BACnetEngineeringUnits = 83
	CubicFeetPerSecond                BACnetEngineeringUnits = 142
	CubicFeetPerMinute                BACnetEngineeringUnits = 84
	MillionCubicFeetPerMinute         BACnetEngineeringUnits = 254
	CubicFeetPerHour                  BACnetEngineeringUnits = 191
	StandardCubicFeetPerDay           BACnetEngineeringUnits = 47808
	MillionStandardCubicFeetPerDay    BACnetEngineeringUnits = 47809
	ThousandCubicFeetPerDay           BACnetEngineeringUnits = 47810
	ThousandStandardCubicFeetPerDay   BACnetEngineeringUnits = 47811
	PoundsMassPerDay                  BACnetEngineeringUnits = 47812
	CubicMetersPerSecond              BACnetEngineeringUnits = 85
	CubicMetersPerMinute              BACnetEngineeringUnits = 165
	CubicMetersPerHour                BACnetEngineeringUnits = 135
	ImperialGallonsPerMinute          BACnetEngineeringUnits = 86
	MillilitersPerSecond              BACnetEngineeringUnits = 198
	LitersPerSecond                   BACnetEngineeringUnits = 87
	LitersPerMinute                   BACnetEngineeringUnits = 88
	LitersPerHour                     BACnetEngineeringUnits = 136
	UsGallonsPerMinute                BACnetEngineeringUnits = 89
	UsGallonsPerHour                  BACnetEngineeringUnits = 192
	DegreesAngular                    BACnetEngineeringUnits = 90
	DegreesCelsiusPerHour             BACnetEngineeringUnits = 91
	DegreesCelsiusPerMinute           BACnetEngineeringUnits = 92
	DegreesFahrenheitPerHour          BACnetEngineeringUnits = 93
	DegreesFahrenheitPerMinute        BACnetEngineeringUnits = 94
	JouleSeconds                      BACnetEngineeringUnits = 183
	KilogramsPerCubicMeter            BACnetEngineeringUnits = 186
	KwHoursPerSquareMeter             BACnetEngineeringUnits = 137
	KwHoursPerSquareFoot              BACnetEngineeringUnits = 138
	MegajoulesPerSquareMeter          BACnetEngineeringUnits = 139
	MegajoulesPerSquareFoot           BACnetEngineeringUnits = 140
	NoUnits                           BACnetEngineeringUnits = 95
	NewtonSeconds                     BACnetEngineeringUnits = 187
	NewtonsPerMeter                   BACnetEngineeringUnits = 188
	PartsPerMillion                   BACnetEngineeringUnits = 96
	PartsPerBillion                   BACnetEngineeringUnits = 97
	Percent                           BACnetEngineeringUnits = 98
	PercentObscurationPerFoot         BACnetEngineeringUnits = 143
	PercentObscurationPerMeter        BACnetEngineeringUnits = 144
	PercentPerSecond                  BACnetEngineeringUnits = 99
	PerMinute                         BACnetEngineeringUnits = 100
	PerSecond                         BACnetEngineeringUnits = 101
	PsiPerDegreeFahrenheit            BACnetEngineeringUnits = 102
	Radians                           BACnetEngineeringUnits = 103
	RadiansPerSecond                  BACnetEngineeringUnits = 184
	RevolutionsPerMinute              BACnetEngineeringUnits = 104
	SquareMetersPerNewton             BACnetEngineeringUnits = 185
	WattsPerMeterPerDegreeKelvin      BACnetEngineeringUnits = 189
	WattsPerSquareMeterDegreeKelvin   BACnetEngineeringUnits = 141
	PerMille                          BACnetEngineeringUnits = 207
	GramsPerGram                      BACnetEngineeringUnits = 208
	KilogramsPerKilogram              BACnetEngineeringUnits = 209
	GramsPerKilogram                  BACnetEngineeringUnits = 210
	MilligramsPerGram                 BACnetEngineeringUnits = 211
	MilligramsPerKilogram             BACnetEngineeringUnits = 212
	GramsPerMilliliter                BACnetEngineeringUnits = 213
	GramsPerLiter                     BACnetEngineeringUnits = 214
	MilligramsPerLiter                BACnetEngineeringUnits = 215
	MicrogramsPerLiter                BACnetEngineeringUnits = 216
	GramsPerCubicMeter                BACnetEngineeringUnits = 217
	MilligramsPerCubicMeter           BACnetEngineeringUnits = 218
	MicrogramsPerCubicMeter           BACnetEngineeringUnits = 219
	NanogramsPerCubicMeter            BACnetEngineeringUnits = 220
	GramsPerCubicCentimeter           BACnetEngineeringUnits = 221
	Becquerels                        BACnetEngineeringUnits = 222
	Kilobecquerels                    BACnetEngineeringUnits = 223
	Megabecquerels                    BACnetEngineeringUnits = 224
	Gray                              BACnetEngineeringUnits = 225
	Milligray                         BACnetEngineeringUnits = 226
	Microgray                         BACnetEngineeringUnits = 227
	Sieverts                          BACnetEngineeringUnits = 228
	Millisieverts                     BACnetEngineeringUnits = 229
	Microsieverts                     BACnetEngineeringUnits = 230
	MicrosievertsPerHour              BACnetEngineeringUnits = 231
	Millirems                         BACnetEngineeringUnits = 47814
	MilliremsPerHour                  BACnetEngineeringUnits = 47815
	DecibelsA                         BACnetEngineeringUnits = 232
	NephelometricTurbidityUnit        BACnetEngineeringUnits = 233
	Ph                                BACnetEngineeringUnits = 234
	GramsPerSquareMeter               BACnetEngineeringUnits = 235
	MinutesPerDegreeKelvin            BACnetEngineeringUnits = 236
	MeterSquaredPerMeter              BACnetEngineeringUnits = 237
	AmpereSeconds                     BACnetEngineeringUnits = 238
	VoltAmpereHours                   BACnetEngineeringUnits = 239
	KilovoltAmpereHours               BACnetEngineeringUnits = 240
	MegavoltAmpereHours               BACnetEngineeringUnits = 241
	VoltAmpereHoursReactive           BACnetEngineeringUnits = 242
	KilovoltAmpereHoursReactive       BACnetEngineeringUnits = 243
	MegavoltAmpereHoursReactive       BACnetEngineeringUnits = 244
	VoltSquareHours                   BACnetEngineeringUnits = 245
	AmpereSquareHours                 BACnetEngineeringUnits = 246
	JoulePerHours                     BACnetEngineeringUnits = 247
	CubicFeetPerDay                   BACnetEngineeringUnits = 248
	CubicMetersPerDay                 BACnetEngineeringUnits = 249
	WattHoursPerCubicMeter            BACnetEngineeringUnits = 250
	JoulesPerCubicMeter               BACnetEngineeringUnits = 251
	MolePercent                       BACnetEngineeringUnits = 252
	PascalSeconds                     BACnetEngineeringUnits = 253
	MillionStandardCubicFeetPerMinute BACnetEngineeringUnits = 254
)

type BACnetEscalatorMode int

const (
	BacnetescalatorModeUnknown BACnetEscalatorMode = iota
	BacnetescalatorModeStop
	BACnetEscalatorModeUp
	BACnetEscalatorModeDown
	BACnetEscalatorModeInspection
	BacnetescalatorModeOutOfService
)

type BACnetEscalatorOperationDirection int

const (
	BacnetEscalatorOperationDirectionUnknown BACnetEscalatorOperationDirection = iota
	BACnetEscalatorOperationDirectionStopped
	UpRatedSpeed
	UpReducedSpeed
	DownRatedSpeed
	DownReducedSpeed
)

type BACnetFileAccessMethod int

const (
	RecordAccess BACnetFileAccessMethod = iota
	StreamAccess
)

type BACnetIPMode int

const (
	BacnetIPModeNormal BACnetIPMode = iota
	Foreign
	Bbmd
)

type BACnetLifeSafetyMode int

const (
	BacnetLifeSafetyModeOff BACnetLifeSafetyMode = iota
	Lon
	Test
	Manned
	Unmanned
	Armed
	Disarmed
	Prearmed
	Slow
	Fast
	Disconnected
	Enabled
	BacnetLifeSafetyModeDisabled
	AutomaticReleaseDisabled
	Default
)

type BACnetLifeSafetyOperation int

const (
	BacnetLifeSafetyOperationNone BACnetLifeSafetyOperation = iota
	Silence
	SilenceAudible
	SilenceVisual
	Reset
	ResetAlarm
	ResetFault
	Unsilence
	UnsilenceAudible
	UnsilenceVisual
)

type BACnetLifeSafetyState int

const (
	Quiet BACnetLifeSafetyState = iota
	PreAlarm
	BacnetlifesafetystateAlarm
	BacnetlifesafetystateFault
	FaultPreAlarm
	FaultAlarm
	BacnetlifesafetystateNotReady
	BacnetlifesafetystateActive
	BacnetlifesafetystateTamper
	TestAlarm
	TestActive
	TestFault
	TestFaultAlarm
	Holdup
	Duress
	TamperAlarm
	Abnormal
	BacnetlifesafetystateEmergencyPower
	Delayed
	Blocked
	LocalAlarm
	GeneralAlarm
	Supervisory
	TestSupervisory
)

type BACnetLiftCarDirection int

const (
	BacnetliftcardirectionUnknown BACnetLiftCarDirection = iota
	BacnetliftcardirectionNone
	Stopped
	Up
	Down
	UpAndDown
)

type BACnetLiftCarDoorCommand int

const (
	BACnetLiftCarDoorCommandNone BACnetLiftCarDoorCommand = iota
	Open
	Close
)

type BACnetLiftCarDriveStatus int

const (
	BACnetLiftCarDriveStatusUnknown BACnetLiftCarDriveStatus = iota
	Stationary
	Braking
	Accelerate
	Decelerate
	RatedSpeed
	SingleFloorJump
	TwoFloorJump
	ThreeFloorJump
	MultiFloorJump
)

type BACnetLiftCarMode int

const (
	BACnetLiftCarModeUnknown BACnetLiftCarMode = iota
	BACnetLiftCarModeNormal
	Vip
	Homing
	Parking
	AttendantControl
	FirefighterControl
	BACnetLiftCarModeEmergencyPower
	Inspection
	CabinetRecall
	EarthquakeOperation
	FireOperation
	BACnetLiftCarModeOutOfService
	OccupantEvacuation
)

type BACnetLiftFault int

const (
	ControllerFault BACnetLiftFault = iota
	DriveAndMotorFault
	GovernorAndSafetyGearFault
	LiftShaftDeviceFault
	PowerSupplyFault
	SafetyInterlockFault
	DoorClosingFault
	DoorOpeningFault
	CarStoppedOutsideLandingZone
	CallButtonStuck
	StartFailure
	ControllerSupplyFault
	SelfTestFailure
	RuntimeLimitExceeded
	PositionLost
	DriveTemperatureExceeded
	LoadMeasurementFault
)

type BACnetLiftGroupMode int

const (
	BACnetLiftGroupModeUnknown BACnetLiftGroupMode = iota
	BACnetLiftGroupModeNormal
	DownPeak
	TwoWay
	FourWay
	EmergencyPower
	UpPeak
)

type BACnetLoggingType int

const (
	Polled BACnetLoggingType = iota
	Cov
	Triggered
)

type BACnetMaintenance int

const (
	BACnetMaintenanceNone BACnetMaintenance = iota
	PeriodicTest
	NeedServiceOperational
	NeedServiceInoperative
)

type BACnetNetworkPortCommand int

const (
	BACnetNetworkPortCommandIdle BACnetNetworkPortCommand = iota
	DiscardChanges
	RenewFdRegistration
	RestartSlaveDiscovery
	RenewDhcp
	RestartAutonegotiation
	Disconnect
	RestartPort
)

type BACnetNodeType int

const (
	BACnetNodeTypeUnknown BACnetNodeType = iota
	System
	Network
	BACnetNodeTypeDevice
	Organizational
	Area
	Equipment
	Point
	Collection
	BACnetNodeTypeProperty
	Functional
	BACnetNodeTypeOther
	Subsystem
	Building
	Floor
	Section
	Module
	Tree
	Member
	Protocol
	Room
	Zone
)

type BACnetRelationship int

const (
	BACnetRelationshipUnknown BACnetRelationship = iota
	BACnetRelationshipDefault
	Contains
	ContainedBy
	Uses
	UsedBy
	Commands
	CommandedBy
	Adjusts
	AdjustedBy
	Ingress
	Egress
	SuppliesAir
	ReceivesAir
	SuppliesHotAir
	ReceivesHotAir
	SuppliesCoolAir
	ReceivesCoolAir
	SuppliesPower
	ReceivesPower
	SuppliesGas
	ReceivesGas
	SuppliesWater
	ReceivesWater
	SuppliesHotWater
	ReceivesHotWater
	SuppliesCoolWater
	ReceivesCoolWater
	SuppliesSteam
	ReceivesSteam
)

type BACnetReliability int

const (
	NoFaultDetected BACnetReliability = iota
	NoSensor
	OverRange
	UnderRange
	OpenLoop
	ShortedLoop
	NoOutput
	UnreliableOther
	ProcessError
	MultiStateFault
	ConfigurationError
	CommunicationFailure BACnetReliability = iota + 1
	MemberFault
	MonitoredObjectFault
	Tripped
	LampFailure
	ActivationFailure
	RenewDhcpFailure
	RenewFdRegistrationFailure
	RestartAutoNegotiationFailure
	RestartFailure
	ProprietaryCommandFailure
	FaultsListed
	ReferencedObjectFault
)

type BACnetRestartReason int

const (
	BACnetRestartReasonUnknown BACnetRestartReason = iota
	ColdStart
	WarmStart
	DetectedPowerLost
	DetectedPowerOff
	HardwareWatchdog
	SoftwareWatchdog
	Suspended
)

type BACnetSecurityLevel int

const (
	Incapable BACnetSecurityLevel = iota
	Plain
	Signed
	Encrypted
	SignedEndToEnd
	EncryptedEndToEnd
)

type BACnetPolarity int

const (
	BACnetPolarityNormal BACnetPolarity = iota
	BACnetPolarityReverse
)

type BACnetProtocolLevel int

const (
	Physical BACnetProtocolLevel = iota
	BACnetProtocolLevelProtocol
	BACnetApplication
	NonBACnetApplication
)

type BACnetSilencedState int

const (
	Unsilenced BACnetSilencedState = iota
	AudibleSilenced
	VisibleSilenced
	AllSilenced
)

type BACnetTimerState int

const (
	BACnetTimerStateIdle BACnetTimerState = iota
	Running
	Expired
)

type BACnetTimerTransition int

const (
	BACnetTimerTransitionNone BACnetTimerTransition = iota
	IdleToRunning
	RunningToIdle
	RunningToRunning
	RunningToExpired
	ForcedToExpired
	ExpiredToIdle
	ExpiredToRunning
)

type BACnetVTClass int

const (
	DefaultTerminal BACnetVTClass = iota
	ANSI_X3_64
	DEC_VT52
	DEC_VT100
	DEC_VT220
	HP_700_94
	IBM_3130
)

type BACnetAccessEvent int

const (
	BACnetAccessEventNone BACnetAccessEvent = iota
	Granted
	Muster
	PassbackDetected
	BACnetAccessEventDuress
	Trace
	LockoutMaxAttempts
	LockoutOther
	LockoutRelinquished
	LockedByHigherPriority
	BACnetAccessEventOutOfService
	OutOfServiceRelinquished
	AccompanimentBy
	AuthenticationFactorRead
	BACnetAccessEventAuthorizationDelayed
	BACnetAccessEventVerificationRequired
	NoEntryAfterGrant
	DeniedDenyAll BACnetAccessEvent = iota + 111
	DeniedUnknownCredential
	DeniedAuthenticationUnavailable
	DeniedAuthenticationFactorTimeout
	DeniedIncorrectAuthenticationFactor
	DeniedZoneNoAccessRights
	DeniedPointNoAccessRights
	DeniedNoAccessRights
	DeniedOutOfTimeRange
	DeniedThreatLevel
	DeniedPassback
	DeniedUnexpectedLocationUsage
	DeniedMaxAttempts
	DeniedLowerOccupancyLimit
	DeniedUpperOccupancyLimit
	DeniedAuthenticationFactorLost
	DeniedAuthenticationFactorStolen
	DeniedAuthenticationFactorDamaged
	DeniedAuthenticationFactorDestroyed
	DeniedAuthenticationFactorDisabled
	DeniedAuthenticationFactorError
	DeniedCredentialUnassigned
	DeniedCredentialNotProvisioned
	DeniedCredentialNotYetActive
	DeniedCredentialExpired
	DeniedCredentialManualDisable
	DeniedCredentialLockout
	DeniedCredentialMaxDays
	DeniedCredentialMaxUses
	DeniedCredentialInactivity
	DeniedCredentialDisabled
	DeniedNoAccompaniment
	DeniedIncorrectAccompaniment
	DeniedLockout
	DeniedVerificationFailed
	DeniedVerificationTimeout
	DeniedOther
)

type BACnetLightingInProgress int

const (
	BACnetLightingInProgressIdle BACnetLightingInProgress = iota
	FadeActive
	RampActive
	NotControlled
	BACnetLightingInProgressOther
)

type BACnetLightingOperation int

const (
	BACnetLightingOperationNone BACnetLightingOperation = iota
	FadeTo
	RampTo
	StepUp
	StepDown
	StepOn
	StepOff
	BACnetLightingOperationWarn
	BACnetLightingOperationWarnOff
	BACnetLightingOperationWarnRelinquish
	BACnetLightingOperationStop
)

type BACnetLightingTransition int

const (
	BACnetLightingTransitionNone BACnetLightingTransition = iota
	Fade
	Ramp
)

type BACnetLockStatus int

const (
	Locked BACnetLockStatus = iota
	Unlocked
	LockFault
	Unused
	BACnetLockStatusUnknown
)

type BACnetEscalatorFault int

const (
	BACnetescalatorfaultControllerFault BACnetEscalatorFault = iota
	BACnetescalatorfaultDriveAndMotorFault
	MechanicalComponentFault
	OverspeedFault
	BACnetescalatorfaultPowerSupplyFault
	SafetyDeviceFault
	BACnetescalatorfaultControllerSupplyFault
	BACnetescalatorfaultDriveTemperatureExceeded
	CombPlateFault
)

type BACnetProgramError int

const (
	BACnetProgramErrorNormal = iota
	LoadFailed
	Internal
	BACnetProgramErrorProgram
	BACnetProgramErrorOther
)

type BACnetProgramRequest int

const (
	BACnetProgramRequestReady = iota
	Load
	Run
	Halt
	Restart
	Unload
)

type BACnetProgramState int

const (
	BACnetProgramStateIdle BACnetProgramState = iota
	Loading
	BACnetProgramStateRunning
	Waiting
	Halted
	Unloading
)

type BACnetShedState int

const (
	BACnetShedStateInactive BACnetShedState = iota
	RequestPending
	Compliant
	NonCompliant
)

type BACnetWriteStatus int

const (
	BACnetWriteStatusIdle BACnetWriteStatus = iota
	BACnetWriteStatusInProgress
	Successful
	Failed
)

type VendorSpecificValue int

func DecodeEnumerated(buffer []byte, offset int, lenValue uint32, objType *ObjectType, propID *PropertyIdentifier) (length int, val interface{}) {
	leng, value := DecodeUnsigned(buffer, offset, int(lenValue))
	if propID != nil {
		switch *propID {
		case SegmentationSupported:
			val = BACnetSegmentation(value)
		case PropertyList:
			val = PropertyIdentifier(value)
		case EventType:
			val = BACnetEventType(value)
		case NotifyType:
			val = BACnetNotifyType(value)
		case FaultType:
			val = BACnetFaultType(value)
		case EventState:
			val = BACnetEventState(value)
		case ObjectTypePI:
			val = ObjectType(value)
		case ReasonForDisable:
			val = BACnetAccessCredentialDisableReason(value)
		case CredentialDisable:
			val = BACnetAccessCredentialDisable(value)
		case PassbackMode:
			val = BACnetAccessPassbackMode(value)
		case UserType:
			val = BACnetAccessUserType(value)
		case NetworkNumberQuality:
			val = BACnetNetworkNumberQuality(value)
		case OccupancyState:
			val = BACnetAccessZoneOccupancyState(value)
		case Action:
			if *objType == Loop {
				val = BACnetAction(value)
			}
		case PresentValue, AlarmValue, FeedbackValue, RelinquishDefault:
			switch *objType {
			case BinaryInput, BinaryOutput, BinaryValue:
				val = BACnetBinaryPV(value)
			case AccessDoor:
				val = BACnetDoorValue(value)
			case LifeSafetyPoint, LifeSafetyZone:
				val = BACnetLifeSafetyState(value)
			case LightingOutput:
				val = BACnetBinaryLightingPV(value)
			case LoadControl:
				val = BACnetShedState(value)
			}
		case AuthenticationStatus:
			val = BACnetAuthenticationStatus(value)
		case AuthorizationExemptions:
			val = BACnetAuthorizationExemption(value)
		case AuthorizationMode:
			val = BACnetAuthorizationMode(value)
		case BackupAndRestoreState:
			val = BACnetBackupState(value)
		case SystemStatus:
			val = BACnetDeviceStatus(value)
		case SecuredStatus:
			val = BACnetDoorSecuredStatus(value)
		case DoorStatus, CarDoorStatus:
			val = BACnetDoorStatus(value)
		case Units, CarLoadUnits:
			val = BACnetEngineeringUnits(value)
		case EscalatorMode:
			val = BACnetEscalatorMode(value)
		case OperationDirection:
			val = BACnetEscalatorOperationDirection(value)
		case FileAccessMethod:
			val = BACnetFileAccessMethod(value)
		case OperationExpected:
			val = BACnetLifeSafetyOperation(value)
		case CarDoorCommand:
			val = BACnetLiftCarDoorCommand(value)
		case CarDriveStatus:
			val = BACnetLiftCarDriveStatus(value)
		case CarMode:
			val = BACnetLiftCarMode(value)
		case GroupMode:
			val = BACnetLiftGroupMode(value)
		case LoggingType:
			val = BACnetLoggingType(value)
		case Reliability:
			val = BACnetReliability(value)
		case LastRestartReason:
			val = BACnetRestartReason(value)
		case NetworkType:
			val = BACnetNetworkType(value)
		case BaseDeviceSecurityPolicy:
			val = BACnetSecurityLevel(value)
		case CarMovingDirection, CarAssignedDirection:
			val = BACnetLiftCarDirection(value)
		case BacnetIpMode, BacnetIpv6Mode:
			val = BACnetIPMode(value)
		case MaintenanceRequired:
			val = BACnetMaintenance(value)
		case Polarity:
			val = BACnetPolarity(value)
		case ProtocolLevel:
			val = BACnetProtocolLevel(value)
		case Silenced:
			val = BACnetSilencedState(value)
		case AccessEvent, AccessAlarmEvents, AccessTransactionEvents, FailedAttemptEvents:
			if *objType == AccessPoint {
				val = BACnetAccessEvent(value)
			}
		case LastAccessEvent:
			if *objType == AccessCredential {
				val = BACnetAccessEvent(value)
			}
		case CredentialStatus:
			if *objType == AccessCredential {
				val = BACnetBinaryPV(value)
			}
		case LockStatus:
			if *objType == AccessDoor {
				val = BACnetLockStatus(value)
			}
		case DoorAlarmState, MaskedAlarmValues, AlarmValues, FaultValues:
			switch *objType {
			case AccessDoor:
				val = BACnetDoorAlarmState(value)
			case LifeSafetyPoint, LifeSafetyZone:
				val = BACnetLifeSafetyState(value)
			case Timer:
				val = BACnetTimerState(value)
			}
		case Mode, AcceptedModes:
			if *objType == LifeSafetyPoint || *objType == LifeSafetyZone {
				val = BACnetLifeSafetyMode(value)
			}
		case TrackingValue, LifeSafetyAlarmValues:
			if *objType == LifeSafetyPoint || *objType == LifeSafetyZone {
				val = BACnetLifeSafetyState(value)
			}
		case FaultSignals:
			switch *objType {
			case Escalator:
				val = BACnetEscalatorFault(value)
			case Lift:
				val = BACnetLiftFault(value)
			}
		case InProgress:
			if *objType == LightingOutput {
				val = BACnetLightingInProgress(value)
			}
		case Transition:
			if *objType == LightingOutput {
				val = BACnetLightingTransition(value)
			}
		case Command:
			if *objType == NetworkPort {
				val = BACnetNetworkPortCommand(value)
			}
		case NodeType, SubordinateNodeTypes:
			if *objType == StructuredView {
				val = BACnetNodeType(value)
			}
		case SubordinateRelationships, DefaultSubordinateRelationship:
			if *objType == StructuredView {
				val = BACnetRelationship(value)
			}
		case ReasonForHalt:
			if *objType == Program {
				val = BACnetProgramError(value)
			}
		case ProgramChange:
			if *objType == Program {
				val = BACnetProgramRequest(value)
			}
		case ProgramState:
			if *objType == Program {
				val = BACnetProgramState(value)
			}
		case TimerState:
			if *objType == Timer {
				val = BACnetTimerState(value)
			}
		case LastStateChange:
			if *objType == Timer {
				val = BACnetTimerTransition(value)
			}
		case VtClassesSupported:
			val = BACnetVTClass(value)
		case WriteStatus:
			if *objType == Channel {
				val = BACnetWriteStatus(value)
			}
		default:
			val = VendorSpecificValue(value)
		}

		return leng, val
	}
	return leng, value
}

func EncodeContextEnumerated(tagNumber BACnetApplicationTag, value uint32) []byte {
	length := 0
	if value < 0x100 {
		length = 1
	} else if value < 0x10000 {
		length = 2
	} else if value < 0x1000000 {
		length = 3
	} else {
		length = 4
	}

	return append(EncodeTag(tagNumber, true, length), EncodeUnsigned(value)...)
}
