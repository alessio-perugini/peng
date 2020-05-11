package peng

import (
	"fmt"
	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/google/gopacket/pcap"
	"github.com/influxdata/influxdb-client-go"
	"log"
	"os"
	"os/signal"
	"time"
)

type Peng struct {
	Config *Config
	//Portbitmap *portbitmap.PortBitmap
	ClientFlowBtmp ClientTraffic
	ServerFlowBtmp ServerTraffic
}

type ClientTraffic struct {
	Portbitmap *portbitmap.PortBitmap
	peng       *Peng //TODO u sure?
}

type ServerTraffic struct {
	Portbitmap *portbitmap.PortBitmap
	peng       *Peng //TODO u sure?
}

type Config struct {
	NumberOfBin        uint //TODO forse rimuovere i 2 campi e usare la config del portbitmap
	NumberOfModule     uint
	NumberOfBits       uint
	SaveFilePath       string
	UseInflux          bool
	InfluxUrl          string
	InfluxPort         uint
	InfluxBucket       string
	InfluxOrganization string
	InfluxAuthToken    string
	TimeFrame          time.Duration
}

func New(cfg *Config) *Peng {
	cfg.NumberOfBits = cfg.NumberOfModule / cfg.NumberOfBin
	bitmapConfig := &portbitmap.Config{
		NumberOfBin:  cfg.NumberOfBin,
		SizeBitmap:   cfg.NumberOfModule,
		NumberOfBits: cfg.NumberOfBits,
	}
	var peng = Peng{
		Config: cfg,
		ClientFlowBtmp: ClientTraffic{
			Portbitmap: portbitmap.New(bitmapConfig),
		},
		ServerFlowBtmp: ServerTraffic{
			Portbitmap: portbitmap.New(bitmapConfig),
		},
	}

	peng.ServerFlowBtmp.peng = &peng //TODO ugly stuff here
	peng.ClientFlowBtmp.peng = &peng //TODO ugly stuff here

	return &peng
}

func (p *Peng) Start() {
	getMyIp()

	pHandle, err := pcap.OpenLive(
		"eno1",
		int32(65535),
		false,
		pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer pHandle.Close()

		packet := gopacket.NewPacketSource(pHandle, pHandle.LinkType())

		time.AfterFunc(p.Config.TimeFrame, p.printAllInfo)
		for packet := range packet.Packets() {
			p.inspect(packet)
			//TODO maybe use custom layers to avoid realloc for each packets (memory improvment)
		}
	}()

	// Wait for Ctrl-C
	sig := make(chan os.Signal, 1024)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("got SIGTERM, closing handle")

	// Close the handle
	pHandle.Close()
}

func (cf *ClientTraffic) printInfo() {
	var p = cf
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	influxField := map[string]interface{}{
		"out": totalEntropy,
	}
	p.peng.PushToInfluxDb(influxField)

	//Print some stats
	fmt.Println(p.Portbitmap) //Print all bitmap
	fmt.Println("Bit set: ")
	for i := 0; i < len(p.Portbitmap.InnerBitmap); i++ {
		fmt.Println("bin number [", i, "]    num (bit at 1): ", p.Portbitmap.InnerBitmap[i].GetBitSets())
	}
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", totalEntropy)

	p.Portbitmap.ClearAll()
}

func (sf *ServerTraffic) printInfo() {
	var p = sf
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	influxField := map[string]interface{}{
		"in": totalEntropy,
	}

	p.peng.PushToInfluxDb(influxField)

	//Print some stats
	fmt.Println(p.Portbitmap) //Print all bitmap
	fmt.Println("Bit set: ")
	for i := 0; i < len(p.Portbitmap.InnerBitmap); i++ {
		fmt.Println("bin number [", i, "]    num (bit at 1): ", p.Portbitmap.InnerBitmap[i].GetBitSets())
	}
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", totalEntropy)

	p.Portbitmap.ClearAll()
}

func (p *Peng) printAllInfo() {
	fmt.Println("#[CLIENT]#")
	p.ClientFlowBtmp.printInfo()
	fmt.Println("\n#------------------------------------------------#")
	fmt.Println("#[SERVER]#")
	p.ServerFlowBtmp.printInfo()
	time.AfterFunc(p.Config.TimeFrame, p.printAllInfo)
}

func (p *Peng) PushToInfluxDb(fields map[string]interface{}) {
	if p.Config.InfluxAuthToken == "" {
		return
	}

	client := influxdb2.NewClient(p.Config.InfluxUrl+":"+fmt.Sprint(p.Config.InfluxPort), p.Config.InfluxAuthToken)
	defer client.Close()
	writeApi := client.WriteApi(p.Config.InfluxOrganization, p.Config.InfluxBucket) //non-blocking

	//Send point of system with hostname and values about in and out bits
	point := influxdb2.NewPoint(
		"system",
		map[string]string{
			"entropy": "ports",
		},
		fields,
		time.Now())

	writeApi.WritePoint(point)

	writeApi.Flush() // Force all unwritten data to be sent
}
