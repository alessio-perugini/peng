package peng

import (
	"fmt"
	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/google/gopacket"
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
	Config *Config
	//Portbitmap *portbitmap.PortBitmap
	ClientFlowBtmp ClientFlow
	ServerFlowBtmp ServerFlow

	/*ClientFlow []ClientFlow
	ServerFlow []ServerFlow*/
}

type Flow interface {
	addFlowPort()
	EntropyTotalStandard()
	EntropyTotal()
	EntropyOfEachBin()
	printInfo()
}

type ClientFlow struct {
	TimeFrame  time.Duration
	Portbitmap *portbitmap.PortBitmap
	//Flow
}

type ServerFlow struct {
	TimeFrame  time.Duration
	Portbitmap *portbitmap.PortBitmap
	//Flow
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
		Config: cfg,
		//Portbitmap: portbitmap.New(bitmapConfig),
		ClientFlowBtmp: ClientFlow{
			TimeFrame:  time.Minute,
			Portbitmap: portbitmap.New(bitmapConfig),
		},
		ServerFlowBtmp: ServerFlow{
			TimeFrame:  time.Minute,
			Portbitmap: portbitmap.New(bitmapConfig),
		},
	}
}

func (p *Peng) Start() {
	getMyIp()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println(sig)
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

	time.AfterFunc(time.Minute, p.printInfoAndForceExit)
	for packet := range packet.Packets() {
		p.inspect(packet)
		//TODO multithread?
		//TODO proper handle termination
		//TODO maybe use custom layers to avoid realloc for each packets (memory improvment)
		//TODo maybe spawn goroutine foreach bitmap?
	}
}

func (cf *ClientFlow) printInfo() {
	var p = cf
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	totalStandardEntropy := p.EntropyTotalStandard(binsEntropy)
	//p.PushToInfluxDb("server", totalEntropy, binsEntropy, time.Minute) //TODO generalizzare meglio

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

func (sf *ServerFlow) printInfo() {
	var p = sf
	binsEntropy := p.EntropyOfEachBin()
	totalEntropy := p.EntropyTotal(binsEntropy)
	totalStandardEntropy := p.EntropyTotalStandard(binsEntropy)
	//p.PushToInfluxDb("server", totalEntropy, binsEntropy, time.Minute) //TODO generalizzare meglio

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
