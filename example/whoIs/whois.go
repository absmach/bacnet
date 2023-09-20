package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/absmach/bacnet/pkg/bacnet"
	"github.com/absmach/bacnet/pkg/transport"
	"github.com/absmach/bacnet/pkg/transport/udp"
)

func main() {

	var highLimit, lowLimit uint32 = 4000000, 0
	req := bacnet.WhoIs{
		HighLimit: &highLimit,
		LowLimit:  &lowLimit,
	}
	whoisBytes := req.Encode()

	broads, err := udp.GetBroadcastAddress("127.0.0.6", 47809)
	if err != nil {
		log.Fatalf("failed to encode npdu with error %v", err)
	}
	broads, err = bacnet.NewBACnetAddress(0xFFFF, nil, "127.0.0.255:47809")
	if err != nil {
		log.Fatal(err)
	}

	npdu := bacnet.NewNPDU(broads, nil, nil, nil)
	npdu.Control.SetNetworkPriority(bacnet.NormalMessage)
	npduBytes, err := npdu.Encode()
	if err != nil {
		log.Fatalf("failed to encode npdu with error %v", err)
	}

	apdu := bacnet.APDU{
		PduType:       bacnet.PDUTypeUnconfirmedServiceRequest,
		ServiceChoice: byte(bacnet.ServiceChoiceWhoIs),
	}

	apduBytes := apdu.Encode()

	mes := append(npduBytes, apduBytes...)
	mes = append(mes, whoisBytes...)

	blvc := bacnet.NewBVLC(transport.IP)
	blvcBytes := blvc.Encode(bacnet.BVLCOriginalBroadcastNPDU, uint16(len(mes)+4))
	message := append(blvcBytes, mes...)

	// Define the BACnet broadcast address (255.255.255.255:47808)
	remoteAddr, err := net.ResolveUDPAddr("udp", "127.0.0.6:47809")
	if err != nil {
		fmt.Println("Error resolving remote address:", err)
		return
	}

	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	// Create a UDP connectionBACnetAddress
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	// Send the WhoIsRequest packet
	_, err = conn.Write(message)
	if err != nil {
		log.Fatal("Error sending WhoIsRequest:", err)
	}

	// Wait for responses
	buffer := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Set a timeout for responses

	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout reached, no more responses
				log.Println("No more responses received.")
				break
			}
			log.Println("Error reading response:", err)
			break
		}

		// Process the response (you'll need to parse BACnet responses here)
		response := buffer[:n]
		log.Printf("Received response: %X\n", response)
		blvc := bacnet.BVLC{BVLLTypeBACnetIP: 0x81}
		headerLength, function, msgLength, err := blvc.Decode(response, 0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(response)
		fmt.Printf("headerLength %v BVLCfunction %v msgLen %v\n", headerLength, function, msgLength)
		fmt.Println("blvc", blvc)
		fmt.Println(response[headerLength:])
		npdu := bacnet.NPDU{Version: 1}
		npduLen, err := npdu.Decode(response, headerLength)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("npdu", npdu)
		fmt.Println(response[headerLength+npduLen:])
		apdu := bacnet.APDU{}
		apduLen := apdu.Decode(response, headerLength+npduLen)
		fmt.Println("apdu", apdu)
		fmt.Println(response[headerLength+npduLen+apduLen:])
		iam := bacnet.IAmRequest{}
		iamLen, err := iam.Decode(response, headerLength+npduLen+apduLen)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("iam", iam)
		fmt.Println(response[headerLength+npduLen+apduLen+iamLen:])
	}
}
