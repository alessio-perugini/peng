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
	Config                       *Config
	ClientTraffic, ServerTraffic *portbitmap.PortBitmap
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
		Config:        cfg,
		ClientTraffic: portbitmap.New(bitmapConfig),
		ServerTraffic: portbitmap.New(bitmapConfig),
	}

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

		time.AfterFunc(p.Config.TimeFrame, p.PrintAllInfo)
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

func printInfo(bitmap *portbitmap.PortBitmap) {
	p := bitmap
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)

	//Print some stats
	fmt.Println(p) //Print all bitmap
	fmt.Println("Bit set: ")
	for i := 0; i < len(p.InnerBitmap); i++ {
		fmt.Println("bin number [", i, "]    num (bit at 1): ", p.InnerBitmap[i].GetBitSets())
	}
	fmt.Println("EntropyOfEachBin: ", binsEntropy)
	fmt.Println("EntropyTotal: ", totalEntropy)

	p.ClearAll()
}

func (p *Peng) PrintAllInfo() {
	fmt.Println("#[CLIENT]#")
	printInfo(p.ClientTraffic)
	fmt.Println("\n#------------------------------------------------#\n#[SERVER]#")
	printInfo(p.ServerTraffic)

	p.PushToInfluxDb("out", p.ClientTraffic)
	p.PushToInfluxDb("in", p.ServerTraffic)

	time.AfterFunc(p.Config.TimeFrame, p.PrintAllInfo)
}

func (p *Peng) PushToInfluxDb(name string, portBin *portbitmap.PortBitmap) {
	if p.Config.InfluxAuthToken == "" {
		return
	}

	binsEntropy := portBin.EntropyOfEachBin()
	totalEntropy := portBin.EntropyTotal(binsEntropy)
	fields := map[string]interface{}{
		name: totalEntropy,
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
