package peng

import (
	"fmt"
	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers" //Used to init internal struct
	"github.com/google/gopacket/pcap"
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

		time.AfterFunc(p.Config.TimeFrame, p.handler)
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

func printTrafficInfo(pBtmp *portbitmap.PortBitmap) {
	fmt.Println(pBtmp) //Print all bitmap
	fmt.Println("Bit set: ")
	for i := 0; i < len(pBtmp.InnerBitmap); i++ {
		fmt.Println("bin number [", i, "]    num (bit at 1): ", pBtmp.InnerBitmap[i].GetBitSets())
	}

	fmt.Println("EntropyOfEachBin: ", pBtmp.EntropyOfEachBin())
	fmt.Println("EntropyTotal: ", pBtmp.EntropyTotal())
}

func (p *Peng) PrintAllInfo() {
	fmt.Println("#[CLIENT]#")
	printTrafficInfo(p.ClientTraffic)
	fmt.Println("\n#------------------------------------------------#\n#[SERVER]#")
	printTrafficInfo(p.ServerTraffic)
}

func (p *Peng) handler() {
	p.PushToInfluxDb()
	p.ExportToCsv()

	p.PrintAllInfo()

	//Clear bitmap for the new reader
	p.ClientTraffic.ClearAll()
	p.ServerTraffic.ClearAll()

	//Wait timeframe time, before further actions
	time.AfterFunc(p.Config.TimeFrame, p.handler)
}
