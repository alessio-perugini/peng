package csv

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"
)

type Csv struct {
	path string
}

func New(path string) *Csv {
	return &Csv{path: path}
}

func (c *Csv) Push(in, out []float64) error {
	file, err := os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}

	defer file.Close()

	var csvData = [][]string{
		{
			time.Now().Local().String(),
			fmt.Sprintf("%f", in),
			fmt.Sprintf("%f", out),
		},
	}

	if err = csv.NewWriter(file).WriteAll(csvData); err != nil {
		return err
	}
	if err = file.Chown(65534, 65534); err != nil {
		return err
	}

	return nil
}

func (c *Csv) Stop() {}
