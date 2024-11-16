/*-<==============================================>-*\
 * { MIT Licence									 }
 * { Maintainer: Joeky <joeky5888@gmail.com>	 	 }
 * { Dude that converted this into a library: xplshn }
 *-<==============================================>-*/

package fileident

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	MaxFileLength  = 256
	MaxBytesToRead = 2 * 1024 // 2KB buffer to read file
)

// IdentifyFiles identifies the type of files matching the given pattern.
func IdentifyFiles(pattern string) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		fmt.Println(err)
		return
	}

	longestFileName := 0
	for _, fileName := range files {
		if len(fileName) > longestFileName {
			longestFileName = len(fileName)
		}
	}

	for _, filename := range files {
		fi, err := os.Lstat(filename)
		if err != nil {
			fmt.Print(filename + ": " + err.Error())
			continue
		}

		if len(filename) > MaxFileLength {
			fmt.Print("File name too long.")
			continue
		}

		fmt.Print(filename + ": ")
		for padding := 0; padding < longestFileName+2-len(filename); padding++ {
			fmt.Print(" ")
		}

		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			reallink, _ := os.Readlink(filename)
			fmt.Print("symbolic link to " + reallink)
		case fi.Mode()&os.ModeDir != 0:
			fmt.Print("directory")
		case fi.Mode()&os.ModeSocket != 0:
			fmt.Print("socket")
		case fi.Mode()&os.ModeCharDevice != 0:
			fmt.Print("character special device")
		case fi.Mode()&os.ModeDevice != 0:
			fmt.Print("device file")
		case fi.Mode()&os.ModeNamedPipe != 0:
			fmt.Print("fifo")
		default:
			regularFile(filename)
		}
		fmt.Println()
	}
}

func regularFile(filename string) {
	file, _ := os.OpenFile(filename, os.O_RDONLY, 0666)
	defer file.Close()

	var contentByte = make([]byte, MaxBytesToRead)
	numByte, _ := file.Read(contentByte)
	contentByte = contentByte[:numByte]

	lenb := len(contentByte)
	magic := -1
	if lenb > 112 {
		magic = peekLe(contentByte[60:], 4)
	}

	switch {
	case lenb >= 45 && HasPrefix(contentByte, "\x7FELF"):
		fmt.Print("Elf file ")
		doElf(contentByte)
	case lenb >= 8 && HasPrefix(contentByte, "!<arch>\n"):
		fmt.Print("ar archive")
	case lenb > 28 && HasPrefix(contentByte, "\x89PNG\x0d\x0a\x1a\x0a"):
		fmt.Print("PNG image data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "GIF87a") || HasPrefix(contentByte, "GIF89a")):
		fmt.Print("GIF image data")
	case lenb > 32 && HasPrefix(contentByte, "\xff\xd8"):
		fmt.Print("JPEG / jpg image data")
	case lenb > 8 && HasPrefix(contentByte, "\xca\xfe\xba\xbe"):
		fmt.Print("Java class file")
	case lenb > 8 && HasPrefix(contentByte, "dex\n"):
		fmt.Print("Android dex file")
	case lenb > 500 && Equal(contentByte[257:262], "ustar"):
		fmt.Print("Posix tar archive")
	case lenb > 5 && HasPrefix(contentByte, "PK\x03\x04"):
		fmt.Print(doZip(file))
	case lenb > 4 && HasPrefix(contentByte, "BZh"):
		fmt.Print("bzip2 compressed data")
	case lenb > 10 && HasPrefix(contentByte, "\x1f\x8b"):
		fmt.Print("gzip compressed data")
	case lenb > 32 && Equal(contentByte[1:4], "\xfa\xed\xfe"):
		fmt.Print("Mach-O")
	case lenb > 36 && HasPrefix(contentByte, "OggS\x00\x02"):
		fmt.Print("Ogg data")
	case lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:16], "WAVEfmt "):
		fmt.Print("WAV audio")
	case lenb > 12 && HasPrefix(contentByte, "\x00\x01\x00\x00"):
		fmt.Print("TrueType font")
	case lenb > 12 && HasPrefix(contentByte, "ttcf\x00"):
		fmt.Print("TrueType font collection")
	case lenb > 4 && HasPrefix(contentByte, "BC\xc0\xde"):
		fmt.Print("LLVM IR bitcode")
	case HasPrefix(contentByte, "-----BEGIN CERTIFICATE-----"):
		fmt.Print("PEM certificate")
	case magic != -1 && HasPrefix(contentByte, "MZ") && magic < lenb-4 &&
		Equal(contentByte[magic:magic+4], "\x50\x45\x00\x00"):

		// Linux kernel images look like PE files.
		if Equal(contentByte[56:60], "ARMd") {
			fmt.Print("Linux arm64 kernel image")
			return
		} else if Equal(contentByte[514:518], "HdrS") {
			fmt.Print("Linux x86-64 kernel image")
			return
		}

		fmt.Print("MS PE32")
		if peekLe(contentByte[magic+24:], 2) == 0x20b {
			fmt.Print("+")
		}
		fmt.Print(" executable")
		if peekLe(contentByte[magic+22:], 2)&0x2000 != 0 {
			fmt.Print("(DLL)")
		}
		fmt.Print(" ")
		if peekLe(contentByte[magic+20:], 2) > 70 {
			types := []string{"", "native", "GUI", "console", "OS/2", "driver", "CE",
				"EFI", "EFI boot", "EFI runtime", "EFI ROM", "XBOX", "", "boot"}
			tp := peekLe(contentByte[magic+92:], 2)
			if tp > 0 && tp < len(types) {
				fmt.Print(types[tp])
			} else {
				fmt.Print("unknown")
			}
		}

		// Ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
		switch peekLe(contentByte[magic+4:], 2) {
		case 0x1c0:
			fmt.Print(" arm")
		case 0xaa64:
			fmt.Print(" aarch64")
		case 0x14c:
			fmt.Print(" Intel 80386")
		case 0x8664:
			fmt.Print(" amd64")
		}
	case lenb > 50 && HasPrefix(contentByte, "BM") &&
		Equal(contentByte[6:10], "\x00\x00\x00\x00"):
		fmt.Print("BMP image")
	case lenb > 50 && HasPrefix(contentByte, "\x25\x50\x44\x46"):
		fmt.Print("PDF image")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x49\x49\x2a\x00") || HasPrefix(contentByte, "\x4D\x4D\x00\x2a")):
		fmt.Print("TIFF image data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "ID3") || HasPrefix(contentByte, "\xff\xfb") || HasPrefix(contentByte, "\xff\xf3") || HasPrefix(contentByte, "\xff\xf2")):
		fmt.Print("MP3 audio file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x00\x00\x00\x20\x66\x74\x79\x70") || HasPrefix(contentByte, "\x00\x00\x00\x18\x66\x74\x79\x70") || HasPrefix(contentByte, "\x00\x00\x00\x14\x66\x74\x79\x70")):
		fmt.Print("MP4 video file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x52\x61\x72\x21\x1A\x07\x01\x00")):
		fmt.Print("RAR archive data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x37\x7A\xBC\xAF\x27\x1C")):
		fmt.Print("7zip archive data")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x00\x00\x01\x00")):
		fmt.Print("MS Windows icon resource")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")):
		fmt.Print("SQLite database")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x0A\x0D\x0D\x0A")):
		fmt.Print("PCAP-ng capture file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\xD4\xC3\xB2\xA1") || HasPrefix(contentByte, "\xA1\xB2\xC3\xD4") || HasPrefix(contentByte, "\x4D\x3C\xB2\xA1") || HasPrefix(contentByte, "\xA1\xB2\x3C\x4D")):
		fmt.Print("PCAP capture file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x66\x4C\x61\x43")):
		fmt.Print("FLAC audio format")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x54\x44\x46\x24")):
		fmt.Print("Telegram Desktop file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x54\x44\x45\x46")):
		fmt.Print("Telegram Desktop encrypted file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x4D\x53\x43\x46")):
		fmt.Print("Microsoft Cabinet file")
	case lenb > 16 &&
		(HasPrefix(contentByte, "\x38\x42\x50\x53")):
		fmt.Print("Photoshop document")
	case lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:11], "AVI"):
		fmt.Print("AVI file")
	case lenb > 32 && HasPrefix(contentByte, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
		fmt.Print("Microsoft Office (Legacy format)")
	case lenb > 32 && HasPrefix(contentByte, "RIF") &&
		Equal(contentByte[8:12], "WEBP"):
		fmt.Print("Google Webp file")
	case lenb > 32 && HasPrefix(contentByte, "\x7B\x5C\x72\x74\x66\x31"):
		fmt.Print("Rich Text Format")
	case lenb > 32 && (HasPrefix(contentByte, "<!DOCTYPE html") || (HasPrefix(contentByte, "<head>"))):
		fmt.Print("HTML document")
	case lenb > 32 && (HasPrefix(contentByte, "<?xml version")):
		fmt.Print("XML document")
	}
}

func doElf(contentByte []byte) {
	bits := int(contentByte[4])
	endian := contentByte[5]

	var elfint func(c []byte, size int) int

	if endian == 2 {
		elfint = peekBe
	} else {
		elfint = peekLe
	}

	exei := elfint(contentByte[16:], 2)

	switch exei {
	case 1:
		fmt.Print("relocatable")
	case 2:
		fmt.Print("executable")
	case 3:
		fmt.Print("shared object")
	case 4:
		fmt.Print("core dump")
	default:
		fmt.Print("bad type")
	}

	fmt.Print(", ")

	switch bits {
	case 1:
		fmt.Print("32-bit ")
	case 2:
		fmt.Print("64-bit ")
	}

	switch endian {
	case 1:
		fmt.Print("LSB ")
	case 2:
		fmt.Print("MSB ")
	default:
		fmt.Print("bad endian ")
	}

	/* You can have a full list from here https://golang.org/src/debug/elf/elf.go */
	archType := map[string]int{
		"alpha": 0x9026, "arc": 93, "arcv2": 195, "arm": 40, "arm64": 183,
		"avr32": 0x18ad, "bpf": 247, "blackfin": 106, "c6x": 140, "cell": 23,
		"cris": 76, "frv": 0x5441, "h8300": 46, "hexagon": 164, "ia64": 50,
		"m32r88": 88, "m32r": 0x9041, "m68k": 4, "metag": 174, "microblaze": 189,
		"microblaze-old": 0xbaab, "mips": 8, "mips-old": 10, "mn10300": 89,
		"mn10300-old": 0xbeef, "nios2": 113, "openrisc": 92, "openrisc-old": 0x8472,
		"parisc": 15, "ppc": 20, "ppc64": 21, "s390": 22, "s390-old": 0xa390,
		"score": 135, "sh": 42, "sparc": 2, "sparc8+": 18, "sparc9": 43, "tile": 188,
		"tilegx": 191, "386": 3, "486": 6, "x86-64": 62, "xtensa": 94, "xtensa-old": 0xabc7,
	}

	archj := elfint(contentByte[18:], 2)
	for key, val := range archType {
		if val == archj {
			fmt.Print(key)
			break
		}
	}

	bits--

	phentsize := elfint(contentByte[42+12*bits:], 2)
	phnum := elfint(contentByte[44+12*bits:], 2)
	phoff := elfint(contentByte[28+4*bits:], 4+4*bits)

	dynamic := false

	for i := 0; i < phnum; i++ {
		phdr := contentByte[phoff+i*phentsize:]
		ptpye := elfint(phdr, 4)

		dynamic = (ptpye == 2) || dynamic /*PT_DYNAMIC*/
		if ptpye != 3 /*PT_INTERP*/ && ptpye != 4 /*PT_NOTE*/ {
			continue
		}

		if ptpye == 3 /*PT_INTERP*/ {
			fmt.Print(", dynamically linked")
		}
	}

	if !dynamic {
		fmt.Print(", statically linked")
	}
}
