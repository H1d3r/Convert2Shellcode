package rdi

import _ "embed"

//go:embed srdi_front_v2_x64.bin
var FrontV2X64 []byte

//go:embed srdi_post_v2_x64.bin
var PostV2X64 []byte

//go:embed srdi_front_v2_x86.bin
var FrontV2X86 []byte

//go:embed srdi_post_v2_x86.bin
var PostV2X86 []byte
