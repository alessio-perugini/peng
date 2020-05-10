package peng

import (
	"fmt"
	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/google/gopacket/pcap"
	"github.com/influxdata/influxdb-client-go"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"time"
)

type Peng struct {
	Config     *Config
	Portbitmap *portbitmap.PortBitmap
}

type Config struct {
	NumberOfBin        uint //TODO forse rimuovere i 2 campi e usare la config del portbitmap
	NumberOfModule     uint
	NumberOfBits       uint
	InfluxUrl          string
	InfluxPort         uint
	InfluxBucket       string
	InfluxOrganization string
	InfluxAuthToken    string
}

var (
	myIPs   = make([]net.IP, 0, 2)
	epsilon = math.Nextafter(1.0, 2.0) - 1.0
)

func New(cfg *Config) *Peng {
	cfg.NumberOfBits = cfg.NumberOfModule / cfg.NumberOfBin
	bitmapConfig := &portbitmap.Config{
		NumberOfBin:  cfg.NumberOfBin,
		SizeBitmap:   cfg.NumberOfModule,
		NumberOfBits: cfg.NumberOfBits,
	}

	return &Peng{
		Config:     cfg,
		Portbitmap: portbitmap.New(bitmapConfig),
	}
}

func (p *Peng) Start() {
	getMyIp()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println(sig)
			fmt.Println(p.Portbitmap.InnerBitmap)
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

	time.AfterFunc(time.Minute, p.end)
	for packet := range packet.Packets() {
		p.inspect(packet)
		//TODO multithread?
		//TODO proper handle termination
		//TODO maybe use custom layers to avoid realloc for each packets (memory improvment)
		//TODo maybe spawn goroutine foreach bitmap?
	}
}

func (p *Peng) EntropyTotal(binsEntropy []float64) float64 {
	var totalEntropy float64
	for _, v := range binsEntropy {
		totalEntropy += v
	}

	return totalEntropy / float64(p.Portbitmap.Config.NumberOfBin)
}

//reference https://rosettacode.org/wiki/Entropy
func (p *Peng) EntropyOfEachBin() []float64 {
	var total = float64(p.Portbitmap.Config.NumberOfBits)             //number of bits in the bin
	var sum float64                                                   //used to compute the entropy
	allEntropy := make([]float64, 0, p.Portbitmap.Config.NumberOfBin) //used to calculate entropy of each bin

	for i := 0; i < len(p.Portbitmap.InnerBitmap); i++ {
		bitsAt1 := float64(p.Portbitmap.InnerBitmap[i].GetBitSets()) / total
		bitsAt0 := float64(uint64(p.Portbitmap.Config.NumberOfBits)-p.Portbitmap.InnerBitmap[i].GetBitSets()) / total

		if bitsAt1 > epsilon && bitsAt0 > epsilon {
			sum -= bitsAt1 * math.Log(bitsAt1)
			sum -= bitsAt0 * math.Log(bitsAt0)
		}
		sum = sum / math.Log(2.0)
		//this helps me to identifies the number of scanned port in entropy form
		if bitsAt1 > bitsAt0 { //so i can distinguish if i'm in the range of [0-1] or [1-0] in term of standard gaussian
			sum = 2 - sum //used to allow growth of entropy in wider range [0-2]
		}

		allEntropy = append(allEntropy, sum)
		sum = 0
	}

	return allEntropy
}

func (p *Peng) end() {
	fmt.Println(p.Portbitmap)
	fmt.Println("Bit set: ")
	for i := 0; i < len(p.Portbitmap.InnerBitmap); i++ {
		fmt.Println("pos [", i, "]  num: ", p.Portbitmap.InnerBitmap[i].GetBitSets())
	}

	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	p.PushToInfluxDb("server", totalEntropy, binsEntropy, time.Minute) //TODO generalizzare meglio
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", totalEntropy)

	p.Portbitmap.ClearAll()
	os.Exit(1)
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

func (p *Peng) inspect(packet gopacket.Packet) {
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
			err := p.Portbitmap.AddPort(uint16(tcp.DstPort))
			if err != nil {
				log.Println(err.Error())
			}
		}
	}
}

//TODO generalizzare meglio
func (p *Peng) PushToInfluxDb(typeName string, totalEntropy float64, binsEntropy []float64, interval time.Duration) {
	client := influxdb2.NewClient(p.Config.InfluxUrl+":"+fmt.Sprint(p.Config.InfluxPort), p.Config.InfluxAuthToken)
	defer client.Close()
	writeApi := client.WriteApi(p.Config.InfluxOrganization, p.Config.InfluxBucket) //non-blocking

	//Create fields to send to influx
	influxFields := make(map[string]interface{}, len(binsEntropy)+2)
	//Create a map for all entropy bucket
	for k, v := range binsEntropy {
		influxFields[fmt.Sprintf("bin_%d", k)] = v
	}
	influxFields["interval"] = interval.Minutes()
	influxFields["total_entropy"] = totalEntropy

	//Send point of system with hostname and values about in and out bits
	point := influxdb2.NewPoint(
		"entropy",
		map[string]string{
			"type": typeName,
		},
		influxFields,
		time.Now())

	writeApi.WritePoint(point)

	writeApi.Flush() // Force all unwritten data to be sent
}
