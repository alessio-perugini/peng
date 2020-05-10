package peng

import "math"

//reference https://rosettacode.org/wiki/Entropy
func (sf *ServerFlow) EntropyOfEachBin() []float64 {
	var total = float64(sf.Portbitmap.Config.NumberOfBits)             //number of bits in the bin
	var sum float64                                                    //used to compute the entropy
	allEntropy := make([]float64, 0, sf.Portbitmap.Config.NumberOfBin) //used to calculate entropy of each bin

	for i := 0; i < len(sf.Portbitmap.InnerBitmap); i++ {
		bitsAt1 := float64(sf.Portbitmap.InnerBitmap[i].GetBitSets()) / total
		bitsAt0 := float64(uint64(sf.Portbitmap.Config.NumberOfBits)-sf.Portbitmap.InnerBitmap[i].GetBitSets()) / total

		if bitsAt1 > epsilon && bitsAt0 > epsilon {
			sum -= bitsAt1 * math.Log(bitsAt1)
			sum -= bitsAt0 * math.Log(bitsAt0)
		}
		sum = sum / math.Log(2.0)
		//this helps me to identifies the number of scanned port in entropy form
		if bitsAt1 > bitsAt0 { //so i can distinguish if i'm in the range of [0-1] or [1-0] in term of standard gaussian
			sum = 2 - sum //used to allow growth of entropy in wider range [0-2]
		}

		allEntropy = append(allEntropy, sum)
		sum = 0
	}

	return allEntropy
}

func (cf *ClientFlow) EntropyOfEachBin() []float64 {
	var total = float64(cf.Portbitmap.Config.NumberOfBits)             //number of bits in the bin
	var sum float64                                                    //used to compute the entropy
	allEntropy := make([]float64, 0, cf.Portbitmap.Config.NumberOfBin) //used to calculate entropy of each bin

	for i := 0; i < len(cf.Portbitmap.InnerBitmap); i++ {
		bitsAt1 := float64(cf.Portbitmap.InnerBitmap[i].GetBitSets()) / total
		bitsAt0 := float64(uint64(cf.Portbitmap.Config.NumberOfBits)-cf.Portbitmap.InnerBitmap[i].GetBitSets()) / total

		if bitsAt1 > epsilon && bitsAt0 > epsilon {
			sum -= bitsAt1 * math.Log(bitsAt1)
			sum -= bitsAt0 * math.Log(bitsAt0)
		}
		sum = sum / math.Log(2.0)
		//this helps me to identifies the number of scanned port in entropy form
		if bitsAt1 > bitsAt0 { //so i can distinguish if i'm in the range of [0-1] or [1-0] in term of standard gaussian
			sum = 2 - sum //used to allow growth of entropy in wider range [0-2]
		}

		allEntropy = append(allEntropy, sum)
		sum = 0
	}

	return allEntropy
}

func (cf *ClientFlow) EntropyTotalStandard(binsEntropy []float64) float64 {
	var standardEntropy float64

	for _, v := range binsEntropy {
		if v > 1 {
			standardEntropy += v - 1
		} else {
			standardEntropy += v
		}
	}

	return standardEntropy / float64(cf.Portbitmap.Config.NumberOfBin)
}

func (sf *ServerFlow) EntropyTotalStandard(binsEntropy []float64) float64 {
	var standardEntropy float64

	for _, v := range binsEntropy {
		if v > 1 {
			standardEntropy += v - 1
		} else {
			standardEntropy += v
		}
	}

	return standardEntropy / float64(sf.Portbitmap.Config.NumberOfBin)
}

func (cf *ClientFlow) EntropyTotal(binsEntropy []float64) float64 {
	var totalEntropy float64

	for _, v := range binsEntropy {
		totalEntropy += v
	}

	return totalEntropy / float64(cf.Portbitmap.Config.NumberOfBin)
}

func (sf *ServerFlow) EntropyTotal(binsEntropy []float64) float64 {
	var totalEntropy float64

	for _, v := range binsEntropy {
		totalEntropy += v
	}

	return totalEntropy / float64(sf.Portbitmap.Config.NumberOfBin)
}
