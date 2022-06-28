package peng

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers" // Used to init internal struct
	"github.com/google/gopacket/pcap"

	"github.com/alessio-perugini/peng/pkg/portbitmap"
	"github.com/alessio-perugini/peng/pkg/storage"
)

type Peng struct {
	Config                       Config
	ClientTraffic, ServerTraffic *portbitmap.PortBitmap
}

type Config struct {
	NumberOfBin      uint
	SizeBitmap       uint
	NumberOfBits     uint
	NetworkInterface string
	Verbose          uint
	TimeFrame        time.Duration
	Storages         []storage.Storage
	MyIPs            []net.IP
}

func New(cfg Config) *Peng {
	cfg.NumberOfBits = cfg.SizeBitmap / cfg.NumberOfBin
	bitmapConfig := portbitmap.Config{
		NumberOfBin:  cfg.NumberOfBin,
		SizeBitmap:   cfg.SizeBitmap,
		NumberOfBits: cfg.NumberOfBits,
	}

	return &Peng{
		Config:        cfg,
		ClientTraffic: portbitmap.New(bitmapConfig),
		ServerTraffic: portbitmap.New(bitmapConfig),
	}
}

func (p *Peng) Start(pHandle *pcap.Handle) {
	defer pHandle.Close()

	var isLive uint32
	atomic.StoreUint32(&isLive, 1)
	shutdownDone := make(chan bool, 1)

	go func() {
		packet := gopacket.NewPacketSource(pHandle, pHandle.LinkType())
		t := time.AfterFunc(p.Config.TimeFrame, p.handler)

		for packet := range packet.Packets() {
			if atomic.LoadUint32(&isLive) == 0 {
				break
			}
			p.inspect(packet)
		}

		t.Stop()
		shutdownDone <- true
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	atomic.StoreUint32(&isLive, 0)
	<-shutdownDone

	for _, v := range p.Config.Storages {
		v.Stop()
	}

	log.Println("Quitting Peng, bye!")
}

func (p *Peng) printAllInfo(client, server *portbitmap.PortBitmap) {
	allPortTraffic := []*portbitmap.PortBitmap{client, server}
	for i, v := range allPortTraffic {
		if p.Config.Verbose == 3 {
			log.Println(v)
			log.Println("Bit set: ")
			for j := 0; j < len(v.InnerBitmap); j++ {
				log.Println("bin number [", j, "]    num (bit at 1): ", v.InnerBitmap[j].GetBitSets())
			}
		}
		if p.Config.Verbose >= 1 {
			if i == 0 {
				log.Printf("[%s] [CLIENT] ", time.Now().Local().String())
			} else {
				log.Printf("[%s] [SERVER] ", time.Now().Local().String())
			}
		}
		if p.Config.Verbose >= 2 {
			log.Printf("entropy of each bin: %f\n", v.EntropyOfEachBin())
		}
		if p.Config.Verbose >= 1 {
			log.Printf("total entropy: %f\n", v.EntropyTotal())
		}
	}
}

func (p *Peng) handler() {
	cTotalEntropy, sTotalEntropy := p.ClientTraffic.EntropyTotal(), p.ServerTraffic.EntropyTotal()
	for _, v := range p.Config.Storages {
		go func(v storage.Storage) {
			if err := v.Push(cTotalEntropy, sTotalEntropy); err != nil {
				log.Println(err)
			}
		}(v)
	}

	if p.Config.Verbose >= 1 {
		p.printAllInfo(p.ClientTraffic, p.ServerTraffic)
	}

	// Clear bitmap for the new reader
	p.ClientTraffic.ClearAll()
	p.ServerTraffic.ClearAll()

	// Wait timeframe time, before further actions
	time.AfterFunc(p.Config.TimeFrame, p.handler)
}
