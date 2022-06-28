package util

import "net"

func GetMyIps() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	myIPs := make([]net.IP, 0, len(addrs))

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			myIPs = append(myIPs, ipnet.IP)
		}
	}

	return myIPs, nil
}
