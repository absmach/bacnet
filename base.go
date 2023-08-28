package bacnet

type NetworkPriority int

const (
	LifeSafetyMessage NetworkPriority = iota + 1
	CriticalEquipmentMessage
	UrgentMessage
	NormalMessage
)

type NetworkLayerMessage int

const (
	WhoIsRouterToNetwork NetworkLayerMessage = iota
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
