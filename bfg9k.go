package main

import (
	"bfg9k/common"
	"bfg9k/encryption"
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"image/png"
	"os"
	"reflect"
	"sort"
	"sync"

	"github.com/at-wat/ebml-go"
	"github.com/auyer/steganography"
	"github.com/peterbourgon/ff/v3"
)

func main() {

	fs := flag.NewFlagSet("bfg9k", flag.ExitOnError)

	var (
		function      = fs.String("function", "", "encrypt or decrypt")
		typ           = fs.String("type", "", "png or mkv")
		inputFile     = fs.String("input", "", "input file")
		victimImage   = fs.String("victim", "", "victim png or mkv")
		outputFile    = fs.String("output", "", "output file")
		encryptionKey = fs.String("key", "", "encryption key")
		chunkSize     = fs.Int("chunk", 400*1024, "chunk size")
		cores         = fs.Int("cores", 32, "number of cores to use")
	)

	err := ff.Parse(fs, os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *function == "" {
		fmt.Println("Function is required! Use encrypt or decrypt")
		os.Exit(1)
	}

	if *typ == "" {
		fmt.Println("Type is required! Use png or mkv")
		os.Exit(1)
	}

	if *inputFile == "" {
		fmt.Println("Input file is required!")
		os.Exit(1)
	}

	if *outputFile == "" {
		fmt.Println("Output file is required!")
		os.Exit(1)
	}

	switch *typ {
	case "png":
		switch *function {
		case "encrypt":
			if *victimImage == "" {
				fmt.Println("Victim image is required!")
				os.Exit(1)
			}

			err := encryptFileToImage(*inputFile, *victimImage, *outputFile, []byte(*encryptionKey))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		case "decrypt":
			err := decryptImageToFile(*inputFile, *outputFile, []byte(*encryptionKey))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		default:
			fmt.Println("Invalid function! Use encrypt or decrypt")
			os.Exit(1)
		}
	case "mkv":
		switch *function {
		case "encrypt":
			if *victimImage == "" {
				fmt.Println("Victim image is required!")
				os.Exit(1)
			}

			err := encryptFileToMKV(*inputFile, *victimImage, *outputFile, []byte(*encryptionKey), *chunkSize, *cores)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		case "decrypt":
			err := decryptMKVToFile(*inputFile, *outputFile, []byte(*encryptionKey), *chunkSize, *cores)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		default:
			fmt.Println("Invalid function! Use encrypt or decrypt")
			os.Exit(1)
		}
	}

	return
}

func encryptFileToMKV(inputFile, inputMKV, outputFile string, key []byte, chunkSize int, cores int) error {
	// Read the input file
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	fmt.Println("Size of the content:", common.HumanFileSize(int64(len(content))))

	// Encrypt the content
	edata, err := encryption.Encrypt(key, content)
	if err != nil {
		return err
	}

	var chunks [][]byte
	for i := 0; i < len(edata); i += chunkSize {
		end := i + chunkSize
		if end > len(edata) {
			end = len(edata)
		}
		chunks = append(chunks, edata[i:end])
	}

	iMKV, err := os.Open(inputMKV)
	if err != nil {
		return err
	}

	// Create a new image
	var dmkv = make(map[string]any)

	err = ebml.Unmarshal(iMKV, &dmkv)
	if err != nil {
		return err
	}

	var count int
	for _, x := range dmkv["Segment"].(map[string]any)["Cluster"].([]any) {
		for _, y := range x.(map[string]any) {
			_, ok := y.([]any)
			if !ok {
				continue
			}
			for _, z := range y.([]any) {
				b, ok := z.(ebml.Block)
				if !ok {
					continue
				}
				if !b.Keyframe {
					continue
				}
				if b.TrackNumber != 1 {
					continue
				}

				count++
			}
		}
	}

	if count < len(chunks) {
		return fmt.Errorf("Not enough clusters in the MKV file Real: %d Needed: %d, Max Available Size: %s", count, len(chunks), common.HumanFileSize(int64(count*chunkSize)))
	} else {
		fmt.Println("Enough clusters in the MKV file Real:", count, "Needed:", len(chunks), "Max Available Size:", common.HumanFileSize(int64(count*chunkSize)))
	}

	type newFrame struct {
		frame   []byte
		cluster int
		block   int
	}

	var counter int64
	var newFrames []newFrame
	var shouldBreak bool
	var mux sync.Mutex
	var wg sync.WaitGroup
	var sem = common.NewSemaphore(cores)

	for c, x := range dmkv["Segment"].(map[string]any)["Cluster"].([]any) {

		for s, y := range x.(map[string]any)["SimpleBlock"].([]any) {

			if counter >= int64(len(chunks)) {
				shouldBreak = true
				break
			}

			b, ok := y.(ebml.Block)
			if !ok {
				continue
			}
			if !b.Keyframe {
				continue
			}
			if b.TrackNumber != 1 {
				continue
			}

			wg.Add(1)
			sem.Acquire()
			go func(counter int64) {
				defer sem.Release()
				defer wg.Done()

				img, err := png.Decode(bytes.NewReader(b.Data[0]))
				if err != nil {
					fmt.Println("Error decoding the image:", err)
					return
				}

				// Encode the encrypted data into the image
				var buf = bytes.NewBuffer(nil)
				err = steganography.Encode(buf, img, chunks[counter])
				if err != nil {
					fmt.Println("Error encoding the data into the image:", err)
					return
				}

				f := newFrame{
					frame:   buf.Bytes(),
					cluster: c,
					block:   s,
				}

				mux.Lock()
				newFrames = append(newFrames, f)
				mux.Unlock()

			}(counter)

			fmt.Printf("\rProgress: %d / %d", counter, len(chunks))
			counter++
		}

		if shouldBreak {
			break
		}
	}

	wg.Wait()
	fmt.Println("\nDone encoding", counter, "chunks")

	// Update the map with the new frames
	for i, f := range newFrames {
		dmkv["Segment"].(map[string]any)["Cluster"].([]any)[f.cluster].(map[string]any)["SimpleBlock"].([]any)[f.block].(ebml.Block).Data[0] = f.frame
		fmt.Printf("\rUpdated frame: %d / %d", i, len(newFrames))
	}

	fmt.Println("\nMarshalling the MKV file")

	os.Remove(outputFile)
	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	err = ebml.Marshal(&dmkv, outFile)
	if err != nil {
		return fmt.Errorf("Error marshalling the MKV file: %v", err)
	}
	fmt.Println("Done marshalling the MKV file")

	return nil
}

func decryptMKVToFile(inputMKV, outputFile string, key []byte, chunkSize int, cores int) error {

	iMKV, err := os.Open(inputMKV)
	if err != nil {
		return err
	}

	// Create a new image
	var dmkv = make(map[string]any)

	err = ebml.Unmarshal(iMKV, &dmkv)
	if err != nil {
		return err
	}

	var count int
	for _, x := range dmkv["Segment"].(map[string]any)["Cluster"].([]any) {
		for _, y := range x.(map[string]any) {
			_, ok := y.([]any)
			if !ok {
				continue
			}
			for _, z := range y.([]any) {
				b, ok := z.(ebml.Block)
				if !ok {
					continue
				}
				if !b.Keyframe {
					continue
				}
				if b.TrackNumber != 1 {
					continue
				}

				count++
			}
		}
	}

	type frame struct {
		frame []byte
		order int
	}

	var frames []frame
	var shouldBreak bool
	var hasStarted bool
	var counter int
	var sem = common.NewSemaphore(cores)
	var wg sync.WaitGroup
	var mux sync.Mutex

	for _, x := range dmkv["Segment"].(map[string]any)["Cluster"].([]any) {
		for _, y := range x.(map[string]any)["SimpleBlock"].([]any) {

			if shouldBreak {
				break
			}

			b, ok := y.(ebml.Block)
			if !ok {
				fmt.Println("Not a block", reflect.TypeOf(y))
				continue
			}

			if !b.Keyframe {
				continue
			}
			if b.TrackNumber != 1 {
				continue
			}
			counter++

			wg.Add(1)
			sem.Acquire()
			go func(counter int) {
				defer sem.Release()
				defer wg.Done()

				// Decode the data from the image
				image := bytes.NewBuffer(b.Data[0])
				i, err := png.Decode(image)
				if err != nil {
					return
				}

				block := steganography.Decode(steganography.GetMessageSizeFromImage(i), i)

				// If the block is less than or equal to chunk size, then we can assume that it's the correct block
				if len(block) <= chunkSize {
					hasStarted = true

					f := frame{
						frame: block,
						order: counter,
					}
					mux.Lock()
					frames = append(frames, f)
					mux.Unlock()
					fmt.Printf("\rProgress: %d Out of %d Potential Frames", counter, count)
				} else if hasStarted {
					shouldBreak = true
				}
			}(counter)

			if shouldBreak {
				break
			}
		}

		if shouldBreak {
			break
		}
	}

	wg.Wait()
	fmt.Println("\nDone decoding", counter, "frames")

	fmt.Println("Sorting the frames and decrypting the data")
	sort.Slice(frames, func(i, j int) bool {
		return frames[i].order < frames[j].order
	})

	// Decrypt the data
	var data []byte
	for _, f := range frames {
		if len(f.frame) == 0 || f.frame == nil {
			continue
		}
		data = append(data, f.frame...)
	}

	data, err = encryption.Decrypt(key, data)
	if err != nil {
		return err
	}

	fmt.Println("Decrypted data size:", common.HumanFileSize(int64(len(data))))

	// Write the decrypted data to the output file
	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func encryptFileToImage(inputFile, inputImage, outputFile string, key []byte) error {
	// Read the input file
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	victimImage, err := os.Open(inputImage)
	if err != nil {
		return err
	}
	defer victimImage.Close()

	// Encrypt the content
	edata, err := encryption.Encrypt(key, content)
	if err != nil {
		return err
	}

	// Create a new image
	outputImage := bytes.NewBuffer(nil)
	dvi, err := png.Decode(victimImage)
	if err != nil {
		return err
	}

	// Encode the encrypted data into the image
	err = steganography.Encode(outputImage, dvi, edata)
	if err != nil {
		return err
	}

	err = os.WriteFile(outputFile, outputImage.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func decryptImageToFile(inputImage, outputFile string, key []byte) error {
	// Read the input image
	victimImage, err := os.Open(inputImage)
	if err != nil {
		return err
	}
	defer victimImage.Close()

	// Decode the data from the image
	reader := bufio.NewReader(victimImage)
	dvi, err := png.Decode(reader)
	if err != nil {
		return err
	}

	// Decrypt the data
	edata := steganography.Decode(steganography.GetMessageSizeFromImage(dvi), dvi)
	data, err := encryption.Decrypt(key, edata)
	if err != nil {
		return err
	}

	// Write the decrypted data to the output file
	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
