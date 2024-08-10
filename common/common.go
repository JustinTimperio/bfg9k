package common

import (
	"io"
	"math"
	"strconv"

	"github.com/klauspost/compress/zstd"
)

var suffixes = [6]string{"B", "KB", "MB", "GB", "TB", "PB"}

// HumanFileSize converts a int64 representing the number of bytes
// into a human readable string
func HumanFileSize(size int64) string {
	floatSize := float64(size)
	if floatSize <= 0 {
		return "Empty File"
	}

	base := math.Log(floatSize) / math.Log(1024)
	getSize := round(math.Pow(1024, base-math.Floor(base)), .5, 2)

	suffixBase := int(math.Floor(base))
	if suffixBase < 0 || suffixBase > 5 {
		return "File Size is out of Index"
	}
	getSuffix := suffixes[int(math.Floor(base))]

	return strconv.FormatFloat(getSize, 'f', -1, 64) + " " + string(getSuffix)
}

func round(val float64, roundOn float64, places int) float64 {
	var round float64
	pow := math.Pow(10, float64(places))
	digit := pow * val
	_, div := math.Modf(digit)
	if div >= roundOn {
		round = math.Ceil(digit)
	} else {
		round = math.Floor(digit)
	}
	return round / pow
}

type Semaphore interface {
	Acquire()
	Release()
	Close()
}

type semaphore struct {
	semC chan struct{}
}

func NewSemaphore(maxConcurrency int) Semaphore {
	return &semaphore{
		semC: make(chan struct{}, maxConcurrency),
	}
}

func (s *semaphore) Acquire() {
	s.semC <- struct{}{}
}

func (s *semaphore) Release() {
	<-s.semC
}

// Is this needed?
func (s *semaphore) Close() {
	close(s.semC)
}

// ZstdDecompressReader decompresses the input data from the provided reader using Zstandard compression algorithm
// and writes the decompressed data to the provided writer.
// It returns an error if the decompression fails.
func ZstdDecompressReader(in io.Reader, out io.Writer) error {
	d, err := zstd.NewReader(in)
	if err != nil {
		return err
	}
	defer d.Close()

	// Copy content...
	_, err = io.Copy(out, d)
	return err
}

// ZstdCompressReader compresses the data from the input reader using Zstandard compression algorithm
// and writes the compressed data to the output writer.
// It returns an error if any error occurs during the compression process.
func ZstdCompressReader(in io.Reader, out io.Writer) error {
	enc, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, in)
	if err != nil {
		enc.Close()
		return err
	}
	return enc.Close()
}
