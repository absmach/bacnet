package udp

import (
	"context"
	"net"
	"time"

	"github.com/absmach/bacnet/pkg/bacnet"
	"github.com/absmach/bacnet/pkg/transport"
)

var _ transport.Transport = (*client)(nil)

type client struct {
	conn *net.UDPConn
}

// NewClient creates a new trasnport interface for BACnet/IP via UDP.
func NewClient(ipAddress string) (transport.Transport, error) {
	udp, err := net.ResolveUDPAddr("udp", ipAddress)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udp)
	if err != nil {
		return nil, err
	}
	return &client{conn: conn}, nil
}

// Send sends a message payload after adding the header and returns the response on a channel.
func (c *client) Send(ctx context.Context, address string, payload []byte, BVLCFunction int, res chan []byte) error {

	blvc := bacnet.NewBVLC(transport.IP)
	blvcBytes := blvc.Encode(bacnet.BVLCFunctions(BVLCFunction), uint16(len(payload)+4))
	message := append(blvcBytes, payload...)

	remoteAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	if _, err := c.conn.WriteTo(message, remoteAddr); err != nil {
		return err
	}

	buffer := make([]byte, 1500)
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for {
		n, _, err := c.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return err
		}

		res <- buffer[:n]
		return nil
	}
	return nil
}

// Close closes the udp connection.
func (c *client) Close() error {
	return c.conn.Close()
}
