package main

import (
	"fmt"
	"net"
	"time"

	"github.com/absmach/bacnet"
)

func main() {
	var highlim, lowLim uint32 = 4194303, 0
	whi := bacnet.WhoIs{HighLimit: &highlim, LowLimit: &lowLim}
	whoIsRequest := whi.Encode()

	// Define the BACnet broadcast address (255.255.255.255:47808)
	remoteAddr, err := net.ResolveUDPAddr("udp", "127.0.0.255:47809")
	if err != nil {
		fmt.Println("Error resolving remote address:", err)
		return
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		fmt.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	// Send the WhoIsRequest packet
	_, err = conn.Write(whoIsRequest)
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
