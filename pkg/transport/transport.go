package transport

import "context"

// TransportMethod network method to transport messages.
type TransportMethod int

const (
	// IP BACnet IP transport via UDP.
	IP TransportMethod = iota
)

// Transport interface to send messages and return responses on the network layer.
type Transport interface {
	// Send sends a message payload after adding the header and returns the response on a channel.
	Send(ctx context.Context, address string, payload []byte, BVLCFunction int, res chan []byte) error
	// Close closes the network connection.
	Close() error
}
