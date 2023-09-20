package main

import (
	"context"
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
	valTag := encoding.Real
	req := bacnet.WritePropertyRequest{
		PropertyIdentifier: encoding.PresentValue,
		ObjectIdentifier:   bacnet.ObjectIdentifier{Type: encoding.AnalogInput, Instance: 10},
		PropertyValue:      []bacnet.BACnetValue{{Tag: &valTag, Value: float32(22.55)}},
	}
	if err := client.WriteProperty(context.Background(), "127.0.0.6:47809", req); err == nil {
		log.Println("successful write")
	} else {
		log.Fatal(err)
	}
}
