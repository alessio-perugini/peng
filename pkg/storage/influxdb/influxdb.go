package influxdb

import (
	"fmt"
	influxdb2 "github.com/influxdata/influxdb-client-go"
	"github.com/influxdata/influxdb-client-go/api"
	"time"
)

type Config struct {
	InfluxUrl          string
	InfluxPort         uint
	InfluxBucket       string
	InfluxOrganization string
	InfluxAuthToken    string
}

type InfluxDB struct {
	client influxdb2.Client
	writer api.WriteAPI
	cfg    Config
}

func New(cfg Config) *InfluxDB {
	client := influxdb2.NewClient(fmt.Sprintf("%s:%d", cfg.InfluxUrl, cfg.InfluxPort), cfg.InfluxAuthToken)
	return &InfluxDB{
		client: client,
		writer: client.WriteAPI(cfg.InfluxOrganization, cfg.InfluxBucket),
		cfg:    cfg,
	}
}

// Push Send point of system with hostname and values about in and out bits
func (i *InfluxDB) Push(in, out []float64) error {
	point := influxdb2.NewPoint(
		"system",
		map[string]string{
			"entropy": "ports",
		},
		map[string]interface{}{
			"in":  in,
			"out": out,
		},
		time.Now(),
	)

	i.writer.WritePoint(point)

	return nil
}

func (i *InfluxDB) Stop() {
	i.client.Close()
}
