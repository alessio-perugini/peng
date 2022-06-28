package peng

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/alessio-perugini/peng/pkg/portbitmap"
)

func (p *Peng) inspect(packet gopacket.Packet) {
	var ipv4Layer gopacket.Layer // skip inspection if I can't obtain ip layer
	if ipv4Layer = packet.Layer(layers.LayerTypeIPv4); ipv4Layer == nil {
		return
	}

	ipv4, _ := ipv4Layer.(*layers.IPv4)
	var packetDestToMyPc bool
	for _, ip := range p.Config.MyIPs {
		if ipv4.SrcIP.Equal(ip) {
			break
		}
		if !packetDestToMyPc && ipv4.DstIP.Equal(ip) {
			packetDestToMyPc = true
			break
		}
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if !tcp.SYN || tcp.ACK {
		return
	}

	if packetDestToMyPc {
		addPortToBitmap(uint16(tcp.DstPort), p.ServerTraffic)
	} else {
		addPortToBitmap(uint16(tcp.DstPort), p.ClientTraffic)
	}

	if p.Config.Verbose == 3 {
		if packetDestToMyPc {
			log.Printf("[%s] server traffic: %s\n", time.Now().Local().String(), tcp.DstPort.String())
		} else {
			log.Printf("[%s] client traffic: %s\n", time.Now().Local().String(), tcp.DstPort.String())
		}
	}
}

func addPortToBitmap(port uint16, pBitmap *portbitmap.PortBitmap) {
	if err := pBitmap.AddPort(port); err != nil {
		log.Println(err.Error())
	}
}
