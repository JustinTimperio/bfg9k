package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/JustinTimperio/bfg9k/image"
	"github.com/JustinTimperio/bfg9k/video"

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
	} else if _, err := os.Stat(*inputFile); os.IsNotExist(err) {
		fmt.Println("Input file does not exist!")
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

			err := image.EncryptFileToImage(*inputFile, *victimImage, *outputFile, []byte(*encryptionKey))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		case "decrypt":
			err := image.DecryptImageToFile(*inputFile, *outputFile, []byte(*encryptionKey))
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

			err := video.EncryptFileToMKV(*inputFile, *victimImage, *outputFile, []byte(*encryptionKey), *chunkSize, *cores, *truncate, *shards, *parity)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		case "decrypt":
			err := video.DecryptMKVToFile(*inputFile, *outputFile, []byte(*encryptionKey), *chunkSize, *cores, *shards, *parity)
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
