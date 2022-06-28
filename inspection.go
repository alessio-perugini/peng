package peng

import (
	"fmt"
	"log"
	"time"

	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
)

func (p *Peng) inspect(packet gopacket.Packet) {
	var ipv4Layer gopacket.Layer //skip inspection if I can't obtain ip layer
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

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			if packetDestToMyPc {
				addPortToBitmap(uint16(tcp.DstPort), p.ServerTraffic)
			} else {
				addPortToBitmap(uint16(tcp.DstPort), p.ClientTraffic)
			}

			if p.Config.Verbose == 3 {
				if packetDestToMyPc {
					fmt.Printf("[%s] server traffic: %s\n", time.Now().Local().String(), tcp.DstPort.String())
				} else {
					fmt.Printf("[%s] client traffic: %s\n", time.Now().Local().String(), tcp.DstPort.String())
				}
			}
		}
	}
}

func addPortToBitmap(port uint16, pBitmap *portbitmap.PortBitmap) {
	if err := pBitmap.AddPort(port); err != nil {
		log.Println(err.Error())
	}
}
