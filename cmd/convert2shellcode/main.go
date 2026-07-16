package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	convert2shellcode "github.com/onedays12/Convert2Shellcode"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "[-]", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("Convert2Shellcode", flag.ContinueOnError)
	flags.SetOutput(os.Stdout)
	arch := flags.String("arch", "x64", "target architecture: x64 or x86")
	layout := flags.String("type", "front", "RDI layout: front or post")
	input := flags.String("input", "", "input PE path")
	output := flags.String("output", "", "output shellcode path")
	userDataPath := flags.String("user-data", "", "user-data file")
	userDataHex := flags.String("user-data-hex", "", "hex-encoded user data")
	exportName := flags.String("export-name", "", "DLL export name")
	exportHash := flags.String("export-hash", "", "DLL export ROR13 hash")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage:")
		fmt.Fprintln(flags.Output(), "  Convert2Shellcode --arch x64|x86 --type front|post --input <pe> --output <bin> [options]")
		fmt.Fprintln(flags.Output(), "Options:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" {
		flags.Usage()
		return fmt.Errorf("--input and --output are required")
	}
	if *userDataPath != "" && *userDataHex != "" {
		return fmt.Errorf("choose only one: --user-data or --user-data-hex")
	}

	var userData []byte
	var err error
	if *userDataPath != "" {
		userData, err = os.ReadFile(*userDataPath)
		if err != nil {
			return fmt.Errorf("read user data: %w", err)
		}
	} else if *userDataHex != "" {
		userData, err = hex.DecodeString(*userDataHex)
		if err != nil {
			return fmt.Errorf("invalid --user-data-hex")
		}
	}

	var hash uint64
	if *exportHash != "" {
		hash, err = strconv.ParseUint(*exportHash, 0, 32)
		if err != nil {
			return fmt.Errorf("invalid --export-hash")
		}
	}

	pe, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("read input PE: %w", err)
	}
	options := convert2shellcode.Options{
		Arch:       convert2shellcode.Arch(*arch),
		Layout:     convert2shellcode.Layout(*layout),
		UserData:   userData,
		ExportName: *exportName,
		ExportHash: uint32(hash),
	}
	shellcode, err := convert2shellcode.Convert(pe, options)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*output, shellcode, 0o666); err != nil {
		return fmt.Errorf("write shellcode: %w", err)
	}

	fmt.Printf("[+] arch:      %s\n", options.Arch)
	fmt.Printf("[+] type:      %s\n", options.Layout)
	fmt.Printf("[+] input PE:  %d bytes\n", len(pe))
	fmt.Printf("[+] user data: %d bytes\n", len(userData))
	fmt.Printf("[+] output:    %s (%d bytes)\n", *output, len(shellcode))
	return nil
}
