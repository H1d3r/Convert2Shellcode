package convert2shellcode

import (
	"fmt"
	"os"

	"github.com/onedays12/Convert2Shellcode/internal/rdi"
)

// Arch identifies the target PE and RDI loader architecture.
type Arch string

const (
	ArchX64 Arch = "x64"
	ArchX86 Arch = "x86"
)

// Layout identifies where the RDI loader is placed relative to the PE bytes.
type Layout string

const (
	LayoutFront Layout = "front"
	LayoutPost  Layout = "post"
)

// Options controls shellcode generation.
//
// An empty Arch or Layout uses the CLI-compatible defaults: x64 and front.
// When ExportName is set, its ROR13 hash takes precedence over ExportHash,
// matching the legacy C converter.
type Options struct {
	Arch       Arch
	Layout     Layout
	UserData   []byte
	ExportName string
	ExportHash uint32
}

// DefaultOptions returns the CLI-compatible default conversion options.
func DefaultOptions() Options {
	return Options{
		Arch:   ArchX64,
		Layout: LayoutFront,
	}
}

// Convert validates a PE image and produces an RDI shellcode blob.
func Convert(pe []byte, options Options) ([]byte, error) {
	options, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if err := ValidatePE(pe, options.Arch); err != nil {
		return nil, err
	}
	if uint64(len(options.UserData)) > maxUint32 {
		return nil, fmt.Errorf("user data exceeds 4 GiB")
	}

	loader, err := loaderBlob(options.Arch, options.Layout)
	if err != nil {
		return nil, err
	}
	if options.Layout == LayoutFront {
		return buildFront(loader, options.Arch, pe, options.UserData, options.ExportHash)
	}
	return buildPost(loader, options.Arch, pe, options.UserData, options.ExportHash)
}

// ConvertFile reads a PE from inputPath, converts it, and writes shellcode to
// outputPath. It does not create missing output directories.
func ConvertFile(inputPath, outputPath string, options Options) error {
	pe, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input PE: %w", err)
	}
	shellcode, err := Convert(pe, options)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, shellcode, 0o666); err != nil {
		return fmt.Errorf("write shellcode: %w", err)
	}
	return nil
}

// ROR13ExportHash returns the ASCII ROR13 export hash used by the RDI loader.
func ROR13ExportHash(name string) (uint32, error) {
	if name == "" {
		return 0, fmt.Errorf("export name is empty")
	}

	var hash uint32
	for i := 0; i < len(name); i++ {
		if name[i] > 0x7f {
			return 0, fmt.Errorf("export name must be ASCII")
		}
		hash = (hash >> 13) | (hash << 19)
		hash += uint32(name[i])
	}
	if hash == 0 {
		return 0, fmt.Errorf("export name has an invalid ROR13 hash")
	}
	return hash, nil
}

func normalizeOptions(options Options) (Options, error) {
	if options.Arch == "" {
		options.Arch = ArchX64
	}
	if options.Layout == "" {
		options.Layout = LayoutFront
	}
	if options.Arch != ArchX64 && options.Arch != ArchX86 {
		return Options{}, fmt.Errorf("unsupported architecture %q", options.Arch)
	}
	if options.Layout != LayoutFront && options.Layout != LayoutPost {
		return Options{}, fmt.Errorf("unsupported layout %q", options.Layout)
	}
	if options.ExportName != "" {
		hash, err := ROR13ExportHash(options.ExportName)
		if err != nil {
			return Options{}, err
		}
		options.ExportHash = hash
	}
	return options, nil
}

func loaderBlob(arch Arch, layout Layout) ([]byte, error) {
	switch {
	case arch == ArchX64 && layout == LayoutFront:
		return rdi.FrontV2X64, nil
	case arch == ArchX64 && layout == LayoutPost:
		return rdi.PostV2X64, nil
	case arch == ArchX86 && layout == LayoutFront:
		return rdi.FrontV2X86, nil
	case arch == ArchX86 && layout == LayoutPost:
		return rdi.PostV2X86, nil
	default:
		return nil, fmt.Errorf("no RDI loader for %s/%s", arch, layout)
	}
}
