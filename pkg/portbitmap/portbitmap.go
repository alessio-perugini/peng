package portbitmap

import (
	"errors"
	b "github.com/alessio-perugini/peng/pkg/bitmap"
)

type PortBitmap struct {
	Config      *Config
	InnerBitmap []b.Bitmap
	HashFunc    func(port uint16) (uint16, uint64)
}

type Config struct {
	NumberOfBin  uint
	SizeBitmap   uint
	NumberOfBits uint
}

//TODO levare il puntatore a config
func New(cfg *Config) *PortBitmap {
	var InnerBitmap = make([]b.Bitmap, cfg.NumberOfBin)
	cfg.NumberOfBits = cfg.SizeBitmap / cfg.NumberOfBin

	for i := 0; i < int(cfg.NumberOfBin); i++ {
		InnerBitmap[i] = *b.New(uint64(cfg.NumberOfBits))
	}

	var hashFunc = func(port uint16) (uint16, uint64) {
		portModuled := port % uint16(cfg.SizeBitmap)
		index, bit := portModuled/uint16(cfg.NumberOfBits), uint64(portModuled)%uint64(cfg.NumberOfBits)
		return index, bit
	}

	return &PortBitmap{
		InnerBitmap: InnerBitmap,
		HashFunc:    hashFunc,
		Config:      cfg,
	}
}

func (p *PortBitmap) AddPort(port uint16) error {
	indexBin, bitBin := p.HashFunc(port)
	if indexBin >= uint16(len(p.InnerBitmap)) {
		return errors.New("index to access the bin is invalid")
	}
	p.InnerBitmap[indexBin].SetBit(bitBin, true)
	return nil
}

func (p *PortBitmap) ClearAll() {
	for i := 0; i < len(p.InnerBitmap); i++ {
		p.InnerBitmap[i].ResetAllBits()
	}
}
