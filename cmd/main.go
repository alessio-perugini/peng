package main

import (
	"flag"
	"fmt"
	"github.com/alessio-perugini/peng/pkg/util"
	"log"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"

	p "github.com/alessio-perugini/peng"
	"github.com/alessio-perugini/peng/pkg/storage/csv"
	"github.com/alessio-perugini/peng/pkg/storage/influxdb"
)

// nolint
var (
	config = p.Config{
		NumberOfBin: 128,
		SizeBitmap:  1024,
	}
	timeFrame    = "1m"
	saveFilePath string
	influxCfg    = influxdb.Config{
		InfluxURL:          "http://localhost",
		InfluxPort:         9999,
		InfluxBucket:       "",
		InfluxOrganization: "",
		InfluxAuthToken:    "",
	}

	showInterfaceNames bool
	versionFlag        bool
	version            = "0.0.0"
	commit             = "commithash"
)

// nolint
func init() {
	//Bitmap
	flag.UintVar(&config.NumberOfBin, "bin", 16, "number of bin in your bitmap")
	flag.UintVar(&config.SizeBitmap, "size", 1024, "size of your bitmap")

	//influx
	flag.StringVar(&influxCfg.InfluxURL, "influxUrl", "http://localhost", "influx url")
	flag.UintVar(&influxCfg.InfluxPort, "influxPort", 9999, "influxPort number")
	flag.StringVar(&influxCfg.InfluxBucket, "bucket", "", "bucket string for telegraf")
	flag.StringVar(&influxCfg.InfluxOrganization, "org", "", "organization string for telegraf")
	flag.StringVar(&influxCfg.InfluxAuthToken, "token", "", "auth token for influxdb")

	//other
	flag.BoolVar(&versionFlag, "version", false, "output version")
	flag.StringVar(&saveFilePath, "export", "", "file path to save the peng result as csv")
	flag.StringVar(&timeFrame, "timeFrame", "1m", "interval time to detect scans. Number + (s = seconds, m = minutes, h = hours)")
	flag.UintVar(&config.Verbose, "verbose", 1, "set verbose level (1-3)")
	flag.StringVar(&config.NetworkInterface, "network", "", "name of your network interface")
	flag.BoolVar(&showInterfaceNames, "interfaces", false, "show the list of all your network interfaces")
}

func flagConfig() {
	appString := fmt.Sprintf("________                     \n___  __ \\__________________ _\n__  /_/ /  _ \\_  __ \\_  __ `/\n_  ____//  __/  / / /  /_/ / \n/_/     \\___//_/ /_/_\\__, /  \n                    /____/   \n"+
		"version %s %s", version, commit)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\nUsage: sys-status [options]\n", appString)
		flag.PrintDefaults()
	}

	flag.Parse()

	if versionFlag {
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", appString)
		os.Exit(2)
	}

	if showInterfaceNames {
		interfaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err.Error())
		}
		for _, v := range interfaces {
			log.Printf("name: \"%s\"\n\t %s %s %d \n", v.Name, v.Description, v.Addresses, v.Flags)
		}
		os.Exit(2)
	}

	if config.NetworkInterface == "" {
		log.Fatal("You must provide the device adapter you want to listen to")
	}

	if influxCfg.InfluxAuthToken != "" && influxCfg.InfluxBucket == "" && influxCfg.InfluxOrganization == "" {
		log.Fatal("You must provide bucket, organization and influxAuthToken")
	}

	if _, err := url.ParseRequestURI(influxCfg.InfluxURL); err != nil {
		log.Fatal("Influx url is not valid")
	}

	if influxCfg.InfluxAuthToken == "" && saveFilePath == "" {
		log.Fatal("You must provide at least 1 method to send or display the data")
	}

	// Check timeFrame input to perform port scan detection
	v, err := time.ParseDuration(timeFrame)
	if err != nil {
		log.Fatal("Invalid interval format.")
	}
	if v.Seconds() <= 0 {
		log.Fatal("Interval too short it must be at least 1 second long")
	}

	config.TimeFrame = v

	// check if user exceed maximum allowed verbosity
	if config.Verbose > 3 {
		config.Verbose = 3
	}

	if config.SizeBitmap > 1<<16 {
		log.Fatal("Size of full bitmap is too big, it must be less than 65536")
	}

	log.Printf("%s\n", appString)
}

func main() {
	flagConfig()

	myIPs, err := util.GetMyIps()
	if err != nil {
		log.Fatal(err)
	}

	config.MyIPs = myIPs

	if influxCfg.InfluxAuthToken != "" {
		config.Storages = append(config.Storages, influxdb.New(influxCfg))
	}
	if saveFilePath != "" {
		config.Storages = append(config.Storages, csv.New(saveFilePath))
	}

	pHandle, err := pcap.OpenLive(config.NetworkInterface, int32(65535), false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if err = syscall.Setgid(1000); err != nil {
		log.Fatal("Setgid error:", err)
	}
	if err = syscall.Setuid(1000); err != nil {
		log.Fatal("Setuid error:", err)
	}

	p.New(config).Start(pHandle)
}
