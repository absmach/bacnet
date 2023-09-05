package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/absmach/bacnet"
	"github.com/absmach/bacnet/transport"
)

func main() {

	var highLimit, lowLimit uint32 = 4000000, 0
	req := bacnet.WhoIs{
		HighLimit: &highLimit,
		LowLimit:  &lowLimit,
	}
	whoisBytes := req.Encode()

	netType := bacnet.IPV4
	source := bacnet.NewBACnetAddress(20, []byte{}, "127.0.0.255:47809", &netType)

	npdu := bacnet.NewNPDU(source, nil, nil, nil)
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

	fmt.Println(mes)

	blvc := bacnet.NewBVLC(transport.IP)
	blvcBytes := blvc.Encode(bacnet.BVLCOriginalBroadcastNPDU, uint16(len(mes)))
	message := append(blvcBytes, mes...)

	fmt.Println(message)

	// Define the BACnet broadcast address (255.255.255.255:47808)
	remoteAddr, err := net.ResolveUDPAddr("udp", "255.255.255.255:47809")
	if err != nil {
		fmt.Println("Error resolving remote address:", err)
		return
	}

	// Create a UDP connectionBACnetAddress
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	// Send the WhoIsRequest packet
	_, err = conn.Write(message)
	if err != nil {
		fmt.Println("Error sending WhoIsRequest:", err)
		return
	}

	// Wait for responses
	buffer := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Set a timeout for responses

	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout reached, no more responses
				fmt.Println("No more responses received.")
				break
			}
			fmt.Println("Error reading response:", err)
			break
		}

		// Process the response (you'll need to parse BACnet responses here)
		response := buffer[:n]
		fmt.Printf("Received response: %X\n", response)
	}
}
