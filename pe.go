package convert2shellcode

import (
	"encoding/binary"
	"fmt"
)

const (
	maxUint32 = uint64(^uint32(0))

	dosHeaderSize     = 0x40
	dosELfanewOffset  = 0x3c
	ntSignature       = 0x00004550
	fileHeaderSize    = 20
	sectionHeaderSize = 40

	machineI386   = 0x014c
	machineAMD64  = 0x8664
	magicPE32     = 0x010b
	magicPE32Plus = 0x020b

	optional32Size = 224
	optional64Size = 240

	optionalEntryPointOffset  = 16
	optionalImageSizeOffset   = 56
	optionalHeadersSizeOffset = 60
	optional32DirectoryCount  = 92
	optional32DirectoryStart  = 96
	optional64DirectoryCount  = 108
	optional64DirectoryStart  = 112

	directoryImport    = 1
	directoryException = 3
	directoryReloc     = 5
	directoryTLS       = 9
)

// ValidatePE validates the PE structures required by the RDI loader.
func ValidatePE(pe []byte, arch Arch) error {
	if arch == "" {
		arch = ArchX64
	}
	if arch != ArchX64 && arch != ArchX86 {
		return fmt.Errorf("unsupported architecture %q", arch)
	}
	if uint64(len(pe)) > maxUint32 {
		return fmt.Errorf("input PE exceeds 4 GiB")
	}
	if len(pe) < dosHeaderSize || pe[0] != 'M' || pe[1] != 'Z' {
		return fmt.Errorf("input is not a valid DOS PE image")
	}

	ntOffsetSigned := int64(int32(binary.LittleEndian.Uint32(pe[dosELfanewOffset:])))
	if ntOffsetSigned < 0 || !rangeInFile(pe, uint64(ntOffsetSigned), 4+fileHeaderSize+2) {
		return fmt.Errorf("e_lfanew is outside the input file")
	}
	ntOffset := uint64(ntOffsetSigned)
	if readU32(pe, ntOffset) != ntSignature {
		return fmt.Errorf("input has an invalid PE signature")
	}

	fileHeader := ntOffset + 4
	machine := readU16(pe, fileHeader)
	sectionCount := readU16(pe, fileHeader+2)
	optionalSize := uint64(readU16(pe, fileHeader+16))
	optionalStart := fileHeader + fileHeaderSize
	if !rangeInFile(pe, ntOffset, 4+fileHeaderSize+optionalSize) {
		return fmt.Errorf("input has a truncated Optional Header")
	}

	optionalMagic := readU16(pe, optionalStart)
	expectedMachine := uint16(machineAMD64)
	expectedMagic := uint16(magicPE32Plus)
	minimumOptional := uint64(optional64Size)
	directoryCountOffset := uint64(optional64DirectoryCount)
	directoryStartOffset := uint64(optional64DirectoryStart)
	tlsDirectorySize := uint32(40)
	if arch == ArchX86 {
		expectedMachine = machineI386
		expectedMagic = magicPE32
		minimumOptional = optional32Size
		directoryCountOffset = optional32DirectoryCount
		directoryStartOffset = optional32DirectoryStart
		tlsDirectorySize = 24
	}
	if machine != expectedMachine || optionalMagic != expectedMagic || optionalSize < minimumOptional {
		return fmt.Errorf("input PE architecture does not match selected architecture")
	}

	imageSize := readU32(pe, optionalStart+optionalImageSizeOffset)
	headersSize := readU32(pe, optionalStart+optionalHeadersSizeOffset)
	entryRVA := readU32(pe, optionalStart+optionalEntryPointOffset)
	directoryCount := readU32(pe, optionalStart+directoryCountOffset)
	sectionOffset := optionalStart + optionalSize
	sectionBytes := uint64(sectionCount) * sectionHeaderSize
	if imageSize == 0 || headersSize == 0 || headersSize > imageSize ||
		!rangeInFile(pe, 0, uint64(headersSize)) ||
		!rangeInFile(pe, sectionOffset, sectionBytes) ||
		uint64(headersSize) < sectionOffset+sectionBytes {
		return fmt.Errorf("input has invalid PE/section header bounds")
	}
	if entryRVA != 0 && entryRVA >= imageSize {
		return fmt.Errorf("AddressOfEntryPoint is outside SizeOfImage")
	}

	for i := uint64(0); i < uint64(sectionCount); i++ {
		section := sectionOffset + i*sectionHeaderSize
		virtualSize := readU32(pe, section+8)
		virtualAddress := readU32(pe, section+12)
		rawSize := readU32(pe, section+16)
		rawOffset := readU32(pe, section+20)
		mappedSize := virtualSize
		if rawSize > mappedSize {
			mappedSize = rawSize
		}
		if mappedSize != 0 &&
			(uint64(virtualAddress) > uint64(imageSize) ||
				uint64(mappedSize) > uint64(imageSize)-uint64(virtualAddress)) {
			return fmt.Errorf("section %d exceeds SizeOfImage", i)
		}
		if rawSize != 0 && !rangeInFile(pe, uint64(rawOffset), uint64(rawSize)) {
			return fmt.Errorf("section %d raw data exceeds input size", i)
		}
	}

	if err := validateDataDirectory(pe, optionalStart, directoryCount, directoryStartOffset,
		directoryImport, "Import", imageSize, 20); err != nil {
		return err
	}
	if err := validateDataDirectory(pe, optionalStart, directoryCount, directoryStartOffset,
		directoryReloc, "Relocation", imageSize, 8); err != nil {
		return err
	}
	if err := validateDataDirectory(pe, optionalStart, directoryCount, directoryStartOffset,
		directoryTLS, "TLS", imageSize, tlsDirectorySize); err != nil {
		return err
	}
	if arch == ArchX64 {
		if err := validateDataDirectory(pe, optionalStart, directoryCount, directoryStartOffset,
			directoryException, "Exception", imageSize, 12); err != nil {
			return err
		}
	}
	return nil
}

func validateDataDirectory(pe []byte, optionalStart uint64, directoryCount uint32, directoryStart uint64,
	index uint32, name string, imageSize uint32, minimumSize uint32) error {
	var rva, size uint32
	if directoryCount > index {
		offset := optionalStart + directoryStart + uint64(index)*8
		rva = readU32(pe, offset)
		size = readU32(pe, offset+4)
	}
	if (rva == 0) != (size == 0) {
		return fmt.Errorf("%s directory has inconsistent RVA/Size", name)
	}
	if size != 0 &&
		(size < minimumSize || uint64(rva) > uint64(imageSize) || uint64(size) > uint64(imageSize)-uint64(rva)) {
		return fmt.Errorf("%s directory is outside SizeOfImage", name)
	}
	return nil
}

func rangeInFile(data []byte, offset, size uint64) bool {
	return offset <= uint64(len(data)) && size <= uint64(len(data))-offset
}

func readU16(data []byte, offset uint64) uint16 {
	return binary.LittleEndian.Uint16(data[int(offset):])
}

func readU32(data []byte, offset uint64) uint32 {
	return binary.LittleEndian.Uint32(data[int(offset):])
}
