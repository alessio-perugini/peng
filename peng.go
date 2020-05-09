package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/google/gopacket/pcap"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	b "peng/pkg/bitmap"
	"time"
)

//Clear bit &= ^flag
//ToggleFlag ^= flag

var (
	nBin    = 128
	nModule = 1024
	nBits   = uint(nModule / nBin)
	bitmap  = make([]b.Bitmap, nBin)
	myIPs   = make([]net.IP, 0, 2)
	epsilon = math.Nextafter(1.0, 2.0) - 1.0
)

func main() {
	GetMyIp()
	initBitmap()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println(sig)
			fmt.Println(bitmap)
			os.Exit(1)
		}
	}()

	pHandle, err := pcap.OpenLive(
		"eno1",
		int32(65535),
		false,
		pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer pHandle.Close()

	packet := gopacket.NewPacketSource(pHandle, pHandle.LinkType())

	time.AfterFunc(10*time.Second, End)
	for packet := range packet.Packets() {
		inspect(packet)
		//TODO proper handle termination
		//TODO maybe use custom layers to avoid realloc for each packets (memory improvment)
		//TODo maybe spawn goroutine foreach bitmap?
	}
}

func initBitmap() {
	//Create bitmap
	for i := 0; i < nBin; i++ {
		bitmap[i] = *b.New(uint64(nBits))
	}
}

func hash(port uint16) (uint16, uint64) {
	portModuled := port % uint16(nModule)
	index, bit := portModuled/uint16(nBits), uint64(portModuled)%uint64(nBits)
	return index, bit
}

func InsertInBitmap(port uint16) {
	indexBin, bitBin := hash(port)
	bitmap[indexBin].SetBit(bitBin, true)
}

func ResetBitmap() {
	for i := 0; i < len(bitmap); i++ {
		bitmap[i].ResetAllBits()
	}
}

func EntropyTotal(binsEntropy []float64) float64 {
	var totalEntropy float64
	for _, v := range binsEntropy {
		totalEntropy += v
	}

	return totalEntropy / float64(nBin)
}

func EntropyOfEachBin() []float64 {
	var total = float64(nBits)
	var sum float64
	allEntropy := make([]float64, 0, nBin)

	for i := 0; i < len(bitmap); i++ {
		bitsAt1 := float64(bitmap[i].GetBitSets()) / total
		bitsAt0 := float64(uint64(nBits)-bitmap[i].GetBitSets()) / total

		if bitsAt1 > epsilon && bitsAt0 > epsilon {
			sum -= bitsAt1 * math.Log(bitsAt1)
			sum -= bitsAt0 * math.Log(bitsAt0)
		}
		sum = sum / math.Log(2.0)

		if bitsAt1 > bitsAt0 {
			sum = 2 - sum
		}

		allEntropy = append(allEntropy, sum)
		sum = 0
	}

	return allEntropy
}

func End() {
	fmt.Println(bitmap)
	fmt.Println("Bit settati: ")
	for i := 0; i < len(bitmap); i++ {
		fmt.Println("pos [", i, "]  num: ", bitmap[i].GetBitSets())
	}

	binsEntropy := EntropyOfEachBin()
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", EntropyTotal(binsEntropy))

	ResetBitmap()
	os.Exit(1)
}

func GetMyIp() {
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

func inspect(packet gopacket.Packet) {
	var ipv4Layer gopacket.Layer //skip inspection if i can't obtain ip layer
	if ipv4Layer = packet.Layer(layers.LayerTypeIPv4); ipv4Layer == nil {
		return
	}

	//TODO set the ports and split client/server
	ipv4, _ := ipv4Layer.(*layers.IPv4)
	//Discard alla request sent by me!
	var packetDestToMyPc bool
	for _, ip := range myIPs {
		if ipv4.SrcIP.Equal(ip) {
			return
		}
		if !packetDestToMyPc && ipv4.DstIP.Equal(ip) {
			packetDestToMyPc = true
		}
	}
	//Discard the request that doesn't contain my ip on destIp
	if !packetDestToMyPc {
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN {
			InsertInBitmap(uint16(tcp.DstPort))
		}
	}
}
