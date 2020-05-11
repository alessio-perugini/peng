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
	"time"
)

type Peng struct {
	Config *Config
	//Portbitmap *portbitmap.PortBitmap
	ClientFlowBtmp ClientTraffic
	ServerFlowBtmp ServerTraffic
}

/*
type Flow interface {
	addFlowPort()
	EntropyTotalStandard()
	EntropyTotal()
	EntropyOfEachBin()
	printInfo()
	entropyOfEachBin()
}*/

type ClientTraffic struct {
	TimeFrame  time.Duration
	Portbitmap *portbitmap.PortBitmap
	peng       *Peng //TODO u sure?
}

type ServerTraffic struct {
	TimeFrame  time.Duration
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
			TimeFrame:  time.Minute,
			Portbitmap: portbitmap.New(bitmapConfig),
		},
		ServerFlowBtmp: ServerTraffic{
			TimeFrame:  time.Minute,
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
	defer pHandle.Close()

	packet := gopacket.NewPacketSource(pHandle, pHandle.LinkType())

	time.AfterFunc(10*time.Second, p.printInfoAndForceExit)
	for packet := range packet.Packets() {
		p.inspect(packet)
		//TODO multithread?
		//TODO proper handle termination
		//TODO maybe use custom layers to avoid realloc for each packets (memory improvment)
		//TODo maybe spawn goroutine foreach bitmap?
	}
}

func (cf *ClientTraffic) printInfo() {
	var p = cf
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	totalStandardEntropy := p.EntropyTotalStandard(binsEntropy)
	p.peng.PushToInfluxDb("client", totalEntropy) //TODO generalizzare meglio

	//Print some stats
	fmt.Println(p.Portbitmap) //Print all bitmap
	fmt.Println("Bit set: ")
	for i := 0; i < len(p.Portbitmap.InnerBitmap); i++ {
		fmt.Println("bin number [", i, "]    num (bit at 1): ", p.Portbitmap.InnerBitmap[i].GetBitSets())
	}
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", totalEntropy)
	fmt.Println("Total standard entropy: ", totalStandardEntropy)

	p.Portbitmap.ClearAll()
}

func (sf *ServerTraffic) printInfo() {
	var p = sf
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	totalStandardEntropy := p.EntropyTotalStandard(binsEntropy)
	p.peng.PushToInfluxDb("server", totalEntropy) //TODO generalizzare meglio

	//Print some stats
	fmt.Println(p.Portbitmap) //Print all bitmap
	fmt.Println("Bit set: ")
	for i := 0; i < len(p.Portbitmap.InnerBitmap); i++ {
		fmt.Println("bin number [", i, "]    num (bit at 1): ", p.Portbitmap.InnerBitmap[i].GetBitSets())
	}
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", totalEntropy)
	fmt.Println("Total standard entropy: ", totalStandardEntropy)

	p.Portbitmap.ClearAll()
}

func (p *Peng) printInfoAndForceExit() {
	p.ClientFlowBtmp.printInfo()
	fmt.Println("\n#------------------------------------------------#")
	p.ServerFlowBtmp.printInfo()
	os.Exit(1)
}

func (p *Peng) PushToInfluxDb(typeName string, totalEntropy float64) {
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
			"port-entropy": typeName,
		},
		map[string]interface{}{
			"in":  totalEntropy,
			"out": totalEntropy,
		},
		time.Now())

	writeApi.WritePoint(point)

	writeApi.Flush() // Force all unwritten data to be sent
}
