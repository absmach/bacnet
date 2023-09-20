package udp

import (
	"net"
	"strconv"

	"github.com/absmach/bacnet/pkg/bacnet"
)

func GetBroadcastAddress(localEndpoint string, port int) (*bacnet.BACnetAddress, error) {
	broadcast := "255.255.255.255"

	interfaces, err := net.Interfaces()
	if err != nil {
		return &bacnet.BACnetAddress{}, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return &bacnet.BACnetAddress{}, err
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ipAddress := ipnet.IP.String()
				if ipAddress == localEndpoint {
					if iface.Flags&net.FlagBroadcast != 0 {
						broadcast = ipnet.IP.Mask(ipnet.IP.DefaultMask()).String()
					}
				}
			}
		}
	}
	return bacnet.NewBACnetAddress(0xFFFF, nil, broadcast+":"+strconv.Itoa(port))
}
