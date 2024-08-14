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
	"sort"
	"sync"
	"time"

	"github.com/auyer/steganography"
	"github.com/klauspost/reedsolomon"
	"github.com/peterbourgon/ff/v3"
	"gocv.io/x/gocv"
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
		chunkSize     = fs.Int("chunk", 750*1024, "chunk size")
		cores         = fs.Int("cores", 32, "number of cores to use")
		truncate      = fs.Bool("truncate", false, "truncate the output video when all data is encoded")
		shards        = fs.Int("shards", 100, "number of shards to use for Reed-Solomon encoding")
		parity        = fs.Int("replicas", 25, "number of parity shards to use for Reed-Solomon encoding")
	)

	err := ff.Parse(fs, os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *shards+*parity > 255 {
		fmt.Println("Shards and replicas must be less than 255 in total")
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

			err := encryptFileToMKV(*inputFile, *victimImage, *outputFile, []byte(*encryptionKey), *chunkSize, *cores, *truncate, *shards, *parity)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		case "decrypt":
			err := decryptMKVToFile(*inputFile, *outputFile, []byte(*encryptionKey), *chunkSize, *cores, *shards, *parity)
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

type eFrame struct {
	data     gocv.Mat
	position int
}

func encryptFileToMKV(inputFile, inputMKV, outputFile string, key []byte, chunkSize int, cores int, truncate bool, shards, parity int) error {
	// Read the input file
	content, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	inputSize, _ := content.Stat()

	fmt.Println("Size of input file:", common.HumanFileSize(int64(inputSize.Size())))

	compressedBuff := bytes.NewBuffer(nil)
	common.ZstdCompressReader(content, compressedBuff)

	// Encrypt the content
	edata, err := encryption.Encrypt(key, compressedBuff.Bytes())
	if err != nil {
		return err
	}
	fmt.Println("Size of encrypted data:", common.HumanFileSize(int64(len(edata))), "| MD5 Hash:", common.MD5Hash(edata))

	enc, err := reedsolomon.New(shards, parity)
	if err != nil {
		return err
	}

	ecShards, err := enc.Split(edata)
	if err != nil {
		return err
	}

	err = enc.Encode(ecShards)
	if err != nil {
		return err
	}

	// Calculate the size of the data
	var size int
	var parityBytes []byte
	for _, shard := range ecShards {
		parityBytes = append(parityBytes, shard...)
		size += len(shard)
	}

	fmt.Println("Size of encoded data:", common.HumanFileSize(int64(size)), "| MD5:", common.MD5Hash(parityBytes))

	// Disassemble the data into shards in our chunk size
	var chunks [][]byte
	for i := 0; i < len(parityBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(parityBytes) {
			end = len(parityBytes)
		}
		chunks = append(chunks, parityBytes[i:end])
	}

	inputVideo, err := gocv.VideoCaptureFile(inputMKV)
	if err != nil {
		return err
	}
	defer inputVideo.Close()

	if len(chunks) > int(inputVideo.Get(gocv.VideoCaptureFrameCount)) {
		return fmt.Errorf("Not enough frames to encode the data. Can support up to %s", common.HumanFileSize(int64(inputVideo.Get(gocv.VideoCaptureFrameCount)*float64(chunkSize))))
	} else {
		fmt.Println("Video can support up to", common.HumanFileSize(int64(inputVideo.Get(gocv.VideoCaptureFrameCount)*float64(chunkSize))), "of data")
	}

	outputVideo, err := gocv.VideoWriterFile(
		outputFile,
		"MPNG",
		inputVideo.Get(gocv.VideoCaptureFPS),
		int(inputVideo.Get(gocv.VideoCaptureFrameWidth)),
		int(inputVideo.Get(gocv.VideoCaptureFrameHeight)),
		true,
	)

	if err != nil {
		return err
	}
	defer outputVideo.Close()

	var (
		currentFrame      int
		extraFrames       int
		doneSendingFrames bool
		encodingPosition  int
		mux               sync.Mutex
		wg                sync.WaitGroup
		sem               = common.NewSemaphore(cores)
		frames            = make(map[int]eFrame)
	)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	doneChan := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			mux.Lock()
			frame, ok := frames[encodingPosition]
			if !ok {
				mux.Unlock()
				if doneSendingFrames {
					break
				}
				time.Sleep(1 * time.Second)
				continue
			}
			delete(frames, encodingPosition)

			outputVideo.Write(frame.data)
			encodingPosition++
			mux.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		var internalWG sync.WaitGroup
		for {
			frame := gocv.NewMat()
			if !inputVideo.Read(&frame) {
				doneSendingFrames = true
				break
			}

			if currentFrame >= len(chunks) {
				if truncate {
					doneSendingFrames = true
					break
				}

				// If we have reached the end of the data, just write the remaining frames
				mux.Lock()
				frames[currentFrame+extraFrames] = eFrame{data: frame, position: currentFrame}
				mux.Unlock()
				extraFrames++
				continue
			}

			// Only stay ahead of the encoding position by 64 frames
			// Otherwise we blow up the memory usage
			for {
				if currentFrame-encodingPosition < 64 {
					break
				}
				time.Sleep(1 * time.Second)
			}

			sem.Acquire()
			internalWG.Add(1)
			go func(frameNum int, frame gocv.Mat) {
				defer sem.Release()
				defer internalWG.Done()

				buf, err := gocv.IMEncodeWithParams(".png", frame, []int{gocv.IMWritePngCompression, 0})
				if err != nil {
					fmt.Println("Error encoding frame:", err)
					return
				}

				pngImage, err := png.Decode(bytes.NewReader(buf.GetBytes()))
				if err != nil {
					fmt.Println("Error decoding frame:", err)
					return
				}

				maxSize := steganography.MaxEncodeSize(pngImage)
				if maxSize < uint32(chunkSize) {
					panic("Chunk size is larger than the maximum size that can be encoded in the image")
				}

				// Encode the encrypted data into the image
				newImage := bytes.NewBuffer(nil)
				err = steganography.Encode(newImage, pngImage, chunks[frameNum])
				if err != nil {
					fmt.Println("Error encoding data:", err)
					return
				}

				frame, err = gocv.IMDecode(newImage.Bytes(), gocv.IMReadColor)
				if err != nil {
					fmt.Println("Error decoding frame:", err)
					return
				}

				mux.Lock()
				frames[frameNum] = eFrame{data: frame, position: frameNum}
				mux.Unlock()

			}(currentFrame, frame)

			currentFrame++
		}

		internalWG.Wait()
	}()

	go func() {
		wg.Wait()
		doneChan <- struct{}{}
		close(doneChan)
	}()

forLoop:
	for {
		select {
		case <-ticker.C:
			fmt.Printf("\rEncoding data into video | Generation: %d/%d | Encoding: %d/%d", currentFrame, len(chunks), encodingPosition, int(inputVideo.Get(gocv.VideoCaptureFrameCount)))
		case <-doneChan:
			fmt.Println("\nEncoding data into video: Done")
			break forLoop
		}
	}

	if currentFrame < len(chunks) {
		return fmt.Errorf("\nNot enough frames to encode the data")
	}

	return nil
}

type dFrame struct {
	data     []byte
	position int
}

func decryptMKVToFile(inputMKV, outputFile string, key []byte, chunkSize int, cores int, shards, parity int) error {

	inputVideo, err := gocv.VideoCaptureFile(inputMKV)
	if err != nil {
		return err
	}
	defer inputVideo.Close()

	var (
		frames    []dFrame
		sem       = common.NewSemaphore(cores)
		wg        sync.WaitGroup
		mux       sync.Mutex
		counter   int
		lastFrame bool
	)

	for {
		frame := gocv.NewMat()
		if !inputVideo.Read(&frame) {
			break
		}

		if lastFrame {
			break
		}

		wg.Add(1)
		sem.Acquire()

		go func(frameNum int, frame gocv.Mat) {
			defer sem.Release()
			defer wg.Done()

			buf, err := gocv.IMEncodeWithParams(".png", frame, []int{gocv.IMWritePngCompression, 0})
			if err != nil {
				fmt.Println("Error encoding frame:", err)
				return
			}

			pngImage, err := png.Decode(bytes.NewReader(buf.GetBytes()))
			if err != nil {
				fmt.Println("Error decoding frame:", err)
				return
			}

			data := steganography.Decode(steganography.GetMessageSizeFromImage(pngImage), pngImage)
			if len(data) <= chunkSize {
				if len(data) < chunkSize {
					lastFrame = true
				}
				mux.Lock()
				frames = append(frames, dFrame{data: data, position: frameNum})
				mux.Unlock()
				return
			}

			return

		}(counter, frame)

		fmt.Printf("\rDecoding data from video | Frame: %d/%d", counter, int(inputVideo.Get(gocv.VideoCaptureFrameCount)))

		counter++
	}

	wg.Wait()

	if len(frames) == 0 {
		return fmt.Errorf("No data found in the video")
	}

	sort.Slice(frames, func(i, j int) bool {
		return frames[i].position < frames[j].position
	})

	var chunks []byte
	for _, frame := range frames {
		chunks = append(chunks, frame.data...)
	}

	fmt.Println("\nSize of encoded data:", common.HumanFileSize(int64(len(chunks))), "MD5:", common.MD5Hash(chunks))

	var ecShards = make([][]byte, parity+shards)
	var shardSize = len(chunks) / (parity + shards)
	for i := range ecShards {
		start := i * shardSize
		end := start + shardSize
		if start+shardSize > len(chunks) {
			end = len(chunks)
		}

		ecShards[i] = chunks[start:end]
	}

	// Create a Reed-Solomon decoder
	dec, err := reedsolomon.New(shards, parity)
	if err != nil {
		return fmt.Errorf("Error creating Reed-Solomon decoder: %v", err)
	}

	// Verify the parity
	ok, err := dec.Verify(ecShards)
	if err != nil {
		return fmt.Errorf("Error verifying parity: %v", err)
	}
	if !ok {
		err = dec.Reconstruct(ecShards)
		if err != nil {
			return fmt.Errorf("Error reconstructing parity: %v", err)
		}

		ok, err = dec.Verify(ecShards)
		if err != nil {
			return fmt.Errorf("Error verifying parity after reconstruction: %v", err)
		}
		if !ok {
			return fmt.Errorf("Parity check failed a second time")
		}
	}

	// Join the shards into a single data slice
	var buf bytes.Buffer
	err = dec.Join(&buf, ecShards, (shards * shardSize))
	if err != nil {
		return err
	}

	// Trim the zeros from the end of the data
	// TODO: This may cause failures if the data ends with zeros
	for i := len(buf.Bytes()) - 1; i >= 0; i-- {
		if buf.Bytes()[i] == 0 {
			buf.Truncate(i)
		} else {
			break
		}
	}

	fmt.Println("Size of decoded data:", common.HumanFileSize(int64(len(buf.Bytes()))), "MD5:", common.MD5Hash(buf.Bytes()))

	data, err := encryption.Decrypt(key, buf.Bytes())
	if err != nil {
		return err
	}

	// Decompress the data
	decompressedBuff := bytes.NewBuffer(nil)
	err = common.ZstdDecompressReader(bytes.NewBuffer(data), decompressedBuff)
	if err != nil {
		return err
	}
	fmt.Println("Size of decompressed data:", common.HumanFileSize(int64(decompressedBuff.Len())))

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
