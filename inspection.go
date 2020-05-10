package peng

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"log"
	"net"
)

func (p *Peng) inspect(packet gopacket.Packet) {
	var ipv4Layer gopacket.Layer //skip inspection if i can't obtain ip layer
	if ipv4Layer = packet.Layer(layers.LayerTypeIPv4); ipv4Layer == nil {
		return
	}

	ipv4, _ := ipv4Layer.(*layers.IPv4)
	//TODO check if in the flow src and dst non sono entrambe nella mia lista d'ip locale
	var packetDestToMyPc bool
	for _, ip := range myIPs {
		if ipv4.SrcIP.Equal(ip) {
			break
		}
		if !packetDestToMyPc && ipv4.DstIP.Equal(ip) {
			packetDestToMyPc = true
		}
	}
	//Discard the request that doesn't contain my ip on destIp

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN {
			if packetDestToMyPc {
				p.ServerFlowBtmp.addFlowPort(uint16(tcp.DstPort))
			} else {
				p.ClientFlowBtmp.addFlowPort(uint16(tcp.DstPort))
			}
		}
	}
}

//TODO check if i have to make a pointer to FlowMode
func (cf *ClientFlow) addFlowPort(port uint16) {
	err := cf.Portbitmap.AddPort(port)
	if err != nil {
		log.Println(err.Error())
	}
}

func (sf *ServerFlow) addFlowPort(port uint16) {
	err := sf.Portbitmap.AddPort(port)
	if err != nil {
		log.Println(err.Error())
	}
}

func getMyIp() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err.Error())
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				myIPs = append(myIPs, ipnet.IP)
				fmt.Println(ipnet.IP.String())
			}
		}
	}
}
