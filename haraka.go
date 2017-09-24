// Copyright 2017 Kudelski Security and orijtech, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package haraka

import (
	"log"
	"unsafe"
)

var rc = [48 * 4]uint32{
	0x75817b9d, 0xb2c5fef0, 0xe620c00a, 0x0684704c, 0x2f08f717, 0x640f6ba4,
	0x88f3a06b, 0x8b66b4e1, 0x9f029114, 0xcf029d60, 0x53f28498, 0x3402de2d,
	0xfd5b4f79, 0xbbf3bcaf, 0x2e7b4f08, 0x0ed6eae6, 0xbe397044, 0x79eecd1c,
	0x4872448b, 0xcbcfb0cb, 0x2b8a057b, 0x8d5335ed, 0x6e9032b7, 0x7eeacdee,
	0xda4fef1b, 0xe2412761, 0x5e2e7cd0, 0x67c28f43, 0x1fc70b3b, 0x675ffde2,
	0xafcacc07, 0x2924d9b0, 0xb9d465ee, 0xecdb8fca, 0xe6867fe9, 0xab4d63f1,
	0xad037e33, 0x5b2a404f, 0xd4b7cd64, 0x1c30bf84, 0x8df69800, 0x69028b2e,
	0x941723bf, 0xb2cc0bb9, 0x5c9d2d8a, 0x4aaa9ec8, 0xde6f5572, 0xfa0478a6,
	0x29129fd4, 0x0efa4f2e, 0x6b772a12, 0xdfb49f2b, 0xbb6a12ee, 0x32d611ae,
	0xf449a236, 0x1ea10344, 0x9ca8eca6, 0x5f9600c9, 0x4b050084, 0xaf044988,
	0x27e593ec, 0x78a2c7e3, 0x9d199c4f, 0x21025ed8, 0x82d40173, 0xb9282ecd,
	0xa759c9b7, 0xbf3aaaf8, 0x10307d6b, 0x37f2efd9, 0x6186b017, 0x6260700d,
	0xf6fc9ac6, 0x81c29153, 0x21300443, 0x5aca45c2, 0x36d1943a, 0x2caf92e8,
	0x226b68bb, 0x9223973c, 0xe51071b4, 0x6cbab958, 0x225886eb, 0xd3bf9238,
	0x24e1128d, 0x933dfddd, 0xaef0c677, 0xdb863ce5, 0xcb2212b1, 0x83e48de3,
	0xffeba09c, 0xbb606268, 0xc72bf77d, 0x2db91a4e, 0xe2e4d19c, 0x734bd3dc,
	0x2cb3924e, 0x4b1415c4, 0x61301b43, 0x43bb47c3, 0x16eb6899, 0x03b231dd,
	0xe707eff6, 0xdba775a8, 0x7eca472c, 0x8e5e2302, 0x3c755977, 0x6df3614b,
	0xb88617f9, 0x6d1be5b9, 0xd6de7d77, 0xcda75a17, 0xa946ee5d, 0x9d6c069d,
	0x6ba8e9aa, 0xec6b43f0, 0x3bf327c1, 0xa2531159, 0xf957332b, 0xcb1e6950,
	0x600ed0d9, 0xe4ed0353, 0x00da619c, 0x2cee0c75, 0x63a4a350, 0x80bbbabc,
	0x96e90cab, 0xf0b1a5a1, 0x938dca39, 0xab0dde30, 0x5e962988, 0xae3db102,
	0x2e75b442, 0x8814f3a8, 0xd554a40b, 0x17bb8f38, 0x360a16f6, 0xaeb6b779,
	0x5f427fd7, 0x34bb8a5b, 0xffbaafde, 0x43ce5918, 0xcbe55438, 0x26f65241,
	0x839ec978, 0xa2ca9cf7, 0xb9f3026a, 0x4ce99a54, 0x22901235, 0x40c06e28,
	0x1bdff7be, 0xae51a51a, 0x48a659cf, 0xc173bc0f, 0xba7ed22b, 0xa0c1613c,
	0xe9c59da1, 0x4ad6bdfd, 0x02288288, 0x756acc03, 0x848f2ad2, 0x367e4778,
	0x0de7d31e, 0x2ff37238, 0xb73bd58f, 0xee36b135, 0xcf74be8b, 0x08d95c6a,
	0xa3743e4a, 0x66ae1838, 0xc9d6ee98, 0x5880f434, 0x9a9369bd, 0xd0fdf4c7,
	0xaefabd99, 0x593023f0, 0x6f1ecb2a, 0xa5cc637b, 0xeb606e6f, 0x329ae3d1,
	0xcb7594ab, 0xa4dc93d6, 0x49e01594, 0xe00207eb, 0x65208ef8, 0x942366a6,
	0xf751c880, 0x1caa0c4f, 0xe3e67e4a, 0xbd03239f, 0xdb2dc1dd, 0x02f7f57f,
}

func _XT(x byte) byte {
	return (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
}

var rcAsBytes []byte

func init() {
	// The Goal is to convert rc []uint32 --> []byte
	// [48 * 4]uint32 --> [48 * 4 * 4]byte
	nBPerU := 4
	rcAsBytes = make([]byte, 0, len(rc)*8)
	buf := make([]byte, nBPerU)
	nZeros := make([]byte, nBPerU)
	for _, u32 := range rc {
		uint32ToByteSlice(u32, buf, nBPerU)
		rcAsBytes = append(rcAsBytes, buf...)
		copy(buf, nZeros)
	}
	if g, w := len(rcAsBytes), len(rc)*nBPerU; g != w {
		log.Fatalf("rcAsBytes:: length: got=%d want=%d", g, w)
	}
}

// Not using binary.PutUVarint because that requires 5 bytes,
// yet we are trying to maintain C-style byte memory outlays
// where 0xffffffff needs 4 bytes and not 5, for indexing to work.
// See https://play.golang.org/p/bovvliJ_op
func uint32ToByteSlice(u uint32, save []byte, nBytes int) int {
	i := 0
	for u > 0 {
		save[i] = byte(u & 0xff)
		u >>= 8
		i += 1
	}
	return i
}

func _AES2(rci int, s0, s1 []byte) {
	aesenc(s0, rcAsBytes[16*(rci+0):])
	aesenc(s1, rcAsBytes[16*(rci+1):])
	aesenc(s0, rcAsBytes[16*(rci+2):])
	aesenc(s1, rcAsBytes[16*(rci+3):])
}

func _AES4(rci int, s0, s1, s2, s3 []byte) {
	aesenc(s0, rcAsBytes[16*(rci+0):])
	aesenc(s1, rcAsBytes[16*(rci+1):])
	aesenc(s2, rcAsBytes[16*(rci+2):])
	aesenc(s3, rcAsBytes[16*(rci+3):])
	aesenc(s0, rcAsBytes[16*(rci+4):])
	aesenc(s1, rcAsBytes[16*(rci+5):])
	aesenc(s2, rcAsBytes[16*(rci+6):])
	aesenc(s3, rcAsBytes[16*(rci+7):])
}

func _MIX2(tmp []uint32, ss0, ss1 []byte) {
	s0 := *(*[]uint32)(unsafe.Pointer(&ss0))
	s1 := *(*[]uint32)(unsafe.Pointer(&ss1))
	tmp[0] = s0[0]
	tmp[1] = s1[0]
	tmp[2] = s0[1]
	tmp[3] = s1[1]
	s1[0] = s0[2]
	s1[1] = s1[2]
	s1[2] = s0[3]
	s1[3] = s1[3]
	s0[0] = tmp[0]
	s0[1] = tmp[1]
	s0[2] = tmp[2]
	s0[3] = tmp[3]
}

func _MIX4(tmp []uint32, s0, s1, s2, s3 []byte) {
	s0Ptr := *(*[]uint32)(unsafe.Pointer(&s0))
	s1Ptr := *(*[]uint32)(unsafe.Pointer(&s1))
	s2Ptr := *(*[]uint32)(unsafe.Pointer(&s2))
	s3Ptr := *(*[]uint32)(unsafe.Pointer(&s3))
	tmp[0] = s0Ptr[0]
	tmp[1] = s1Ptr[0]
	tmp[2] = s0Ptr[1]
	tmp[3] = s1Ptr[1]
	tmp[4] = s3Ptr[0]
	s0Ptr[0] = s0Ptr[2]
	s0Ptr[1] = s1Ptr[2]
	s0Ptr[2] = s0Ptr[3]
	s0Ptr[3] = s1Ptr[3]
	s1Ptr[0] = s2Ptr[0]
	s1Ptr[1] = s3Ptr[0]
	s1Ptr[2] = s2Ptr[1]
	s1Ptr[3] = s3Ptr[1]
	s2Ptr[0] = s2Ptr[2]
	s2Ptr[1] = s3Ptr[2]
	s2Ptr[2] = s2Ptr[3]
	s2Ptr[3] = s3Ptr[3]
	s3Ptr[0] = s0Ptr[0]
	s3Ptr[1] = s2Ptr[0]
	s3Ptr[2] = s0Ptr[1]
	s3Ptr[3] = s2Ptr[1]
	s0Ptr[0] = s0Ptr[2]
	s0Ptr[1] = s2Ptr[2]
	s0Ptr[2] = s0Ptr[3]
	s0Ptr[3] = s2Ptr[3]
	s2Ptr[0] = s1Ptr[2]
	s2Ptr[1] = tmp[2]
	s2Ptr[2] = s1Ptr[3]
	s2Ptr[3] = tmp[3]
	s1Ptr[0] = s1Ptr[0]
	s1Ptr[1] = tmp[0]
	s1Ptr[2] = tmp[4]
	s1Ptr[3] = tmp[1]
}

func _aesenc(k, s *byte)

// mind the reversed arguments order
func aesenc(s, k []byte) {
	_aesenc(&k[0], &s[0])
}

func Haraka256(out, in []byte) {
	if len(in) == 0 {
		return
	}
	s0 := make([]byte, 16)
	s1 := make([]byte, 16)
	tmp := make([]uint32, 4)

	copy(s0[:], in)
	copy(s1[:], in[16:])

	_AES2(0, s0, s1)
	_MIX2(tmp, s0, s1)
	_AES2(4, s0, s1)
	_MIX2(tmp, s0, s1)
	_AES2(8, s0, s1)
	_MIX2(tmp, s0, s1)
	_AES2(12, s0, s1)
	_MIX2(tmp, s0, s1)
	_AES2(16, s0, s1)
	_MIX2(tmp, s0, s1)
	_AES2(20, s0, s1)
	_MIX2(tmp, s0, s1)

	for i := 0; i < 16; i++ {
		out[i] = in[i] ^ s0[i]
		out[i+16] = in[i+16] ^ s1[i]
	}
}

func Haraka512(out, in []byte) {
	s0 := make([]byte, 16)
	s1 := make([]byte, 16)
	s2 := make([]byte, 16)
	s3 := make([]byte, 16)

	tmp := make([]uint32, 5)
	copy(s0[:], in[0:16])
	copy(s1[:], in[16:32])
	copy(s2[:], in[32:48])
	copy(s3[:], in[48:64])

	_AES4(0, s0, s1, s2, s3)
	_MIX4(tmp, s0, s1, s2, s3)

	_AES4(8, s0, s1, s2, s3)
	_MIX4(tmp, s0, s1, s2, s3)
	_AES4(16, s0, s1, s2, s3)
	_MIX4(tmp, s0, s1, s2, s3)
	_AES4(24, s0, s1, s2, s3)
	_MIX4(tmp, s0, s1, s2, s3)
	_AES4(32, s0, s1, s2, s3)
	_MIX4(tmp, s0, s1, s2, s3)
	_AES4(40, s0, s1, s2, s3)
	_MIX4(tmp, s0, s1, s2, s3)

	for i := 0; i < 16; i++ {
		s0[i] = in[i] ^ s0[i]
		s1[i] = in[i+16] ^ s1[i]
		s2[i] = in[i+32] ^ s2[i]
		s3[i] = in[i+48] ^ s3[i]
	}

	ss0 := *(*[]uint64)(unsafe.Pointer(&s0))
	ss1 := *(*[]uint64)(unsafe.Pointer(&s1))
	ss2 := *(*[]uint64)(unsafe.Pointer(&s2))
	ss3 := *(*[]uint64)(unsafe.Pointer(&s3))
	oout := *(*[]uint64)(unsafe.Pointer(&out))
	oout[0] = ss0[1]
	oout[1] = ss1[1]
	oout[2] = ss2[0]
	oout[3] = ss3[0]
}
