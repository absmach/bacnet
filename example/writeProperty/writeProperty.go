package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/absmach/bacnet/pkg/bacnet"
	"github.com/absmach/bacnet/pkg/encoding"
	"github.com/absmach/bacnet/pkg/transport"
)

func main() {
	netType := encoding.IPV4
	destination := bacnet.NewBACnetAddress(0, nil, "127.0.0.6:47809", &netType)
	npdu := bacnet.NewNPDU(destination, nil, nil, nil)
	npdu.Control.SetDataExpectingReply(true)
	npdu.Control.SetNetworkPriority(bacnet.NormalMessage)

	npduBytes, err := npdu.Encode()
	if err != nil {
		log.Fatal(err)
	}

	apdu := bacnet.APDU{
		PduType:                   bacnet.PDUTypeConfirmedServiceRequest,
		ServiceChoice:             byte(bacnet.WriteProperty),
		SegmentedResponseAccepted: false,
		MaxSegmentsAccepted:       bacnet.BacnetMaxSegments(encoding.NoSegmentation),
		//MaxApduLengthAccepted:     bacnet.MaxAPDU1476,
		InvokeID: 0,
	}

	valTag := encoding.Real

	req := bacnet.WritePropertyRequest{
		PropertyIdentifier: encoding.PresentValue,
		ObjectIdentifier:   bacnet.ObjectIdentifier{Type: encoding.AnalogInput, Instance: 10},
		PropertyValue:      []bacnet.BACnetValue{{Tag: &valTag, Value: float32(22.55)}},
	}

	mes := append(npduBytes, apdu.Encode()...)
	mes = append(mes, req.Encode()...)

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
		//conn.ReadFromUDPAddrPort()
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
		blvc := bacnet.BVLC{BVLLTypeBACnetIP: 0x81}
		headerLength, function, msgLength, err := blvc.Decode(response, 0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("headerLength %v BVLCfunction %v msgLen %v\n", headerLength, function, msgLength)
		fmt.Println("blvc", blvc)
		npdu := bacnet.NPDU{Version: 1}
		npduLen := npdu.Decode(response, headerLength)
		fmt.Println("npdu", npdu)
		apdu := bacnet.APDU{}
		_ = apdu.Decode(response, headerLength+npduLen)
		fmt.Println("apdu", apdu)
	}
}
