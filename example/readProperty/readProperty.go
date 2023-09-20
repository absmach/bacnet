package main

import (
	"context"
	"fmt"
	"log"

	bacClient "github.com/absmach/bacnet"
	"github.com/absmach/bacnet/pkg/bacnet"
	"github.com/absmach/bacnet/pkg/encoding"
	"github.com/absmach/bacnet/pkg/transport/udp"
)

func main() {
	transportClient, err := udp.NewClient("127.0.0.5:47809")
	if err != nil {
		log.Fatal(err)
	}
	defer transportClient.Close()
	client := bacClient.NewClient(transportClient)
	req := bacnet.ReadPropertyRequest{
		PropertyIdentifier: encoding.PresentValue,
		ObjectIdentifier:   &bacnet.ObjectIdentifier{Type: encoding.AnalogInput, Instance: 10},
	}
	val, err := client.ReadProperty(context.Background(), "127.0.0.6:47809", req)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", val)
}
