package transport

import "context"

type TransportMethod int

const (
	IP TransportMethod = iota
)

type Transport interface {
	Send(ctx context.Context, address string, payload []byte, BVLCFunction int, res chan []byte) error
}
