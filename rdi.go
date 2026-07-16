package convert2shellcode

import (
	"encoding/binary"
	"fmt"
)

const (
	rdiMagic      = 0x32494452
	rdiVersion    = 2
	rdiHeaderSize = 0x20
	rdiFlagExport = 0x0001
	maxInt32      = uint32(1<<31 - 1)
)

func buildFront(loader []byte, arch Arch, pe, user []byte, exportHash uint32) ([]byte, error) {
	bootSize := uint32(20)
	if arch == ArchX86 {
		bootSize = 19
	}
	peSize := uint32(len(pe))
	userSize := uint32(len(user))
	loaderSize := uint32(len(loader))
	userOffset := uint32(0)
	if userSize != 0 {
		var err error
		userOffset, err = addU32(rdiHeaderSize, peSize)
		if err != nil {
			return nil, err
		}
	}
	total, err := addU32(bootSize, loaderSize, rdiHeaderSize, peSize, userSize)
	if err != nil {
		return nil, err
	}
	payloadDelta := bootSize + loaderSize - 6
	if payloadDelta > maxInt32 {
		return nil, fmt.Errorf("front bootstrap payload displacement exceeds rel32")
	}

	bootstrap := make([]byte, bootSize)
	bootstrap[0] = 0xfc
	bootstrap[1] = 0xe8
	bootstrap[6] = 0x58
	if arch == ArchX86 {
		bootstrap[7] = 0x8d
		bootstrap[8] = 0x88
		binary.LittleEndian.PutUint32(bootstrap[9:], payloadDelta)
		bootstrap[13] = 0xe8
		binary.LittleEndian.PutUint32(bootstrap[14:], 1)
		bootstrap[18] = 0xc3
	} else {
		bootstrap[7] = 0x48
		bootstrap[8] = 0x8d
		bootstrap[9] = 0x88
		binary.LittleEndian.PutUint32(bootstrap[10:], payloadDelta)
		bootstrap[14] = 0xe8
		binary.LittleEndian.PutUint32(bootstrap[15:], 1)
		bootstrap[19] = 0xc3
	}

	header := buildHeader(peSize, userOffset, userSize, exportHash)
	out := make([]byte, int(total))
	offset := copy(out, bootstrap)
	offset += copy(out[offset:], loader)
	offset += copy(out[offset:], header)
	offset += copy(out[offset:], pe)
	copy(out[offset:], user)
	return out, nil
}

func buildPost(loader []byte, arch Arch, pe, user []byte, exportHash uint32) ([]byte, error) {
	bootSize := uint32(25)
	if arch == ArchX86 {
		bootSize = 19
	}
	peSize := uint32(len(pe))
	userSize := uint32(len(user))
	loaderSize := uint32(len(loader))
	userOffset := uint32(0)
	if userSize != 0 {
		var err error
		userOffset, err = addU32(rdiHeaderSize, peSize)
		if err != nil {
			return nil, err
		}
	}
	rdiOffset, err := addU32(bootSize, rdiHeaderSize, peSize, userSize)
	if err != nil {
		return nil, err
	}
	total, err := addU32(rdiOffset, loaderSize)
	if err != nil {
		return nil, err
	}
	rdiDelta := rdiOffset - 6
	if rdiDelta > maxInt32 {
		return nil, fmt.Errorf("post bootstrap RDI displacement exceeds rel32")
	}

	bootstrap := make([]byte, bootSize)
	bootstrap[0] = 0xfc
	bootstrap[1] = 0xe8
	bootstrap[6] = 0x58
	if arch == ArchX86 {
		bootstrap[7] = 0x8d
		bootstrap[8] = 0x88
		binary.LittleEndian.PutUint32(bootstrap[9:], bootSize-6)
		bootstrap[13] = 0xe8
		binary.LittleEndian.PutUint32(bootstrap[14:], rdiDelta-12)
		bootstrap[18] = 0xc3
	} else {
		bootstrap[7] = 0x48
		bootstrap[8] = 0x8d
		bootstrap[9] = 0x88
		binary.LittleEndian.PutUint32(bootstrap[10:], bootSize-6)
		bootstrap[14] = 0x4c
		bootstrap[15] = 0x8d
		bootstrap[16] = 0x98
		binary.LittleEndian.PutUint32(bootstrap[17:], rdiDelta)
		bootstrap[21] = 0x41
		bootstrap[22] = 0xff
		bootstrap[23] = 0xd3
		bootstrap[24] = 0xc3
	}

	header := buildHeader(peSize, userOffset, userSize, exportHash)
	out := make([]byte, int(total))
	offset := copy(out, bootstrap)
	offset += copy(out[offset:], header)
	offset += copy(out[offset:], pe)
	offset += copy(out[offset:], user)
	copy(out[offset:], loader)
	return out, nil
}

func buildHeader(peSize, userOffset, userSize, exportHash uint32) []byte {
	header := make([]byte, rdiHeaderSize)
	binary.LittleEndian.PutUint32(header[0:], rdiMagic)
	binary.LittleEndian.PutUint16(header[4:], rdiVersion)
	flags := uint16(0)
	if exportHash != 0 {
		flags = rdiFlagExport
	}
	binary.LittleEndian.PutUint16(header[6:], flags)
	binary.LittleEndian.PutUint32(header[8:], rdiHeaderSize)
	binary.LittleEndian.PutUint32(header[12:], peSize)
	binary.LittleEndian.PutUint32(header[16:], userOffset)
	binary.LittleEndian.PutUint32(header[20:], userSize)
	binary.LittleEndian.PutUint32(header[24:], exportHash)
	return header
}

func addU32(values ...uint32) (uint32, error) {
	var total uint64
	for _, value := range values {
		total += uint64(value)
		if total > maxUint32 {
			return 0, fmt.Errorf("shellcode size exceeds 4 GiB")
		}
	}
	return uint32(total), nil
}
