package peng

type Storage interface {
	Push(in, out []float64) error
	Stop()
}
