package image

import (
	"bytes"
	"image/png"
	"os"

	"github.com/JustinTimperio/bfg9k/common"
	"github.com/JustinTimperio/bfg9k/encryption"

	"github.com/auyer/steganography"
)

func EncryptFileToImage(inputFile, inputImage, outputFile string, key []byte) error {
	// Read the input file
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	compressedBuff := bytes.NewBuffer(nil)
	common.ZstdCompressReader(bytes.NewReader(content), compressedBuff)

	victimImage, err := os.Open(inputImage)
	if err != nil {
		return err
	}
	defer victimImage.Close()

	// Encrypt the content
	edata, err := encryption.Encrypt(key, compressedBuff.Bytes())
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

func DecryptImageToFile(inputImage, outputFile string, key []byte) error {
	// Read the input image
	victimImage, err := os.Open(inputImage)
	if err != nil {
		return err
	}
	defer victimImage.Close()

	decompressedBuff := bytes.NewBuffer(nil)
	common.ZstdDecompressReader(victimImage, decompressedBuff)

	// Decode the data from the image
	dvi, err := png.Decode(decompressedBuff)
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
