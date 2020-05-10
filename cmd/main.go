package main

import (
	"flag"
	"fmt"
	p "github.com/alessio-perugini/peng"
	"log"
	"net/url"
	"os"
)

var (
	config = p.Config{
		NumberOfBin:        128,
		NumberOfModule:     1024,
		InfluxUrl:          "http://localhost",
		InfluxPort:         9999,
		InfluxBucket:       "",
		InfluxOrganization: "",
		InfluxAuthToken:    "",
	}

	versionFlag bool
	version     = "0.0.0"
	commit      = "commithash"
)

func init() {
	//Bitmap
	flag.UintVar(&config.NumberOfBin, "bin", 128, "number of bin in your bitmap")
	flag.UintVar(&config.NumberOfModule, "module", 1024, "maximum size of your bitmap")

	//influx
	flag.StringVar(&config.InfluxUrl, "influxUrl", "http://localhost", "influx url")
	flag.UintVar(&config.InfluxPort, "influxPort", 9999, "influxPort number")
	flag.StringVar(&config.InfluxBucket, "bucket", "", "bucket string for telegraf")
	flag.StringVar(&config.InfluxOrganization, "org", "", "organization string for telegraf")
	flag.StringVar(&config.InfluxAuthToken, "token", "", "auth token for influxdb")

	//other
	flag.BoolVar(&versionFlag, "version", false, "output version")
}

func flagConfig() {
	appString := fmt.Sprintf("sys-status version %s %s", version, commit)

	flag.Usage = func() { //help flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\nUsage: sys-status [options]\n", appString)
		flag.PrintDefaults()
	}

	flag.Parse()

	if versionFlag { //version flag
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n", appString)
		os.Exit(2)
	}

	if config.InfluxBucket == "" || config.InfluxOrganization == "" || config.InfluxAuthToken == "" {
		log.Fatal("You must provide bucket, organization and influxAuthToken")
	}

	if _, err := url.ParseRequestURI(config.InfluxUrl); err != nil {
		log.Fatal("Influx url is not valid")
	}

	fmt.Printf("%s\n", appString)
}

func main() {
	flagConfig()
	peng := p.New(&config)
	peng.Start()
}
