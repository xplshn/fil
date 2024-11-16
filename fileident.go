/*-<==============================================>-*\
 * { MIT Licence									 }
 * { Maintainer: Joeky <joeky5888@gmail.com>	 	 }
 * { Dude that converted this into a library: xplshn }
 *-<==============================================>-*/

package fileident

import (
	"os"
	"path/filepath"
)

const (
	maxFileLength  = 256
	maxBytesToRead = 2 * 1024 // 2KB buffer to read file
)

// IdentifyFiles identifies the type of files matching the given pattern.
func IdentifyFiles(pattern string) ([]string, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	longestFileName := 0
	for _, fileName := range files {
		if len(fileName) > longestFileName {
			longestFileName = len(fileName)
		}
	}

	var results []string
	for _, filename := range files {
		fi, err := os.Lstat(filename)
		if err != nil {
			results = append(results, filename+": "+err.Error())
			continue
		}

		if len(filename) > maxFileLength {
			results = append(results, "File name too long.")
			continue
		}

		result := filename + ": "
		for padding := 0; padding < longestFileName+2-len(filename); padding++ {
			result += " "
		}

		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			reallink, _ := os.Readlink(filename)
			result += "symbolic link to " + reallink
		case fi.Mode()&os.ModeDir != 0:
			result += "directory"
		case fi.Mode()&os.ModeSocket != 0:
			result += "socket"
		case fi.Mode()&os.ModeCharDevice != 0:
			result += "character special device"
		case fi.Mode()&os.ModeDevice != 0:
			result += "device file"
		case fi.Mode()&os.ModeNamedPipe != 0:
			result += "fifo"
		default:
			result += regularFile(filename)
		}
		results = append(results, result)
	}
	return results, nil
}

func regularFile(filename string) string {
	file, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		return err.Error()
	}
	defer file.Close()

	var contentByte = make([]byte, maxBytesToRead)
	numByte, err := file.Read(contentByte)
	if err != nil {
		return err.Error()
	}
	contentByte = contentByte[:numByte]

	lenb := len(contentByte)
	magic := -1
	if lenb > 112 {
		magic = peekLe(contentByte[60:], 4)
	}

	switch {
	case lenb >= 45 && hasPrefix(contentByte, "\x7FELF"):
		return "Elf file " + doElf(contentByte)
	case lenb >= 8 && hasPrefix(contentByte, "!<arch>\n"):
		return "ar archive"
	case lenb > 28 && hasPrefix(contentByte, "\x89PNG\x0d\x0a\x1a\x0a"):
		return "PNG image data"
	case lenb > 16 &&
		(hasPrefix(contentByte, "GIF87a") || hasPrefix(contentByte, "GIF89a")):
		return "GIF image data"
	case lenb > 32 && hasPrefix(contentByte, "\xff\xd8"):
		return "JPEG / jpg image data"
	case lenb > 8 && hasPrefix(contentByte, "\xca\xfe\xba\xbe"):
		return "Java class file"
	case lenb > 8 && hasPrefix(contentByte, "dex\n"):
		return "Android dex file"
	case lenb > 500 && equal(contentByte[257:262], "ustar"):
		return "Posix tar archive"
	case lenb > 5 && hasPrefix(contentByte, "PK\x03\x04"):
		return doZip(file)
	case lenb > 4 && hasPrefix(contentByte, "BZh"):
		return "bzip2 compressed data"
	case lenb > 10 && hasPrefix(contentByte, "\x1f\x8b"):
		return "gzip compressed data"
	case lenb > 32 && equal(contentByte[1:4], "\xfa\xed\xfe"):
		return "Mach-O"
	case lenb > 36 && hasPrefix(contentByte, "OggS\x00\x02"):
		return "Ogg data"
	case lenb > 32 && hasPrefix(contentByte, "RIF") &&
		equal(contentByte[8:16], "WAVEfmt "):
		return "WAV audio"
	case lenb > 12 && hasPrefix(contentByte, "\x00\x01\x00\x00"):
		return "TrueType font"
	case lenb > 12 && hasPrefix(contentByte, "ttcf\x00"):
		return "TrueType font collection"
	case lenb > 4 && hasPrefix(contentByte, "BC\xc0\xde"):
		return "LLVM IR bitcode"
	case hasPrefix(contentByte, "-----BEGIN CERTIFICATE-----"):
		return "PEM certificate"
	case magic != -1 && hasPrefix(contentByte, "MZ") && magic < lenb-4 &&
		equal(contentByte[magic:magic+4], "\x50\x45\x00\x00"):

		// Linux kernel images look like PE files.
		if equal(contentByte[56:60], "ARMd") {
			return "Linux arm64 kernel image"
		} else if equal(contentByte[514:518], "HdrS") {
			return "Linux x86-64 kernel image"
		}

		return "MS PE32" + peExecutable(contentByte, magic)
	case lenb > 50 && hasPrefix(contentByte, "BM") &&
		equal(contentByte[6:10], "\x00\x00\x00\x00"):
		return "BMP image"
	case lenb > 50 && hasPrefix(contentByte, "\x25\x50\x44\x46"):
		return "PDF image"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x49\x49\x2a\x00") || hasPrefix(contentByte, "\x4D\x4D\x00\x2a")):
		return "TIFF image data"
	case lenb > 16 &&
		(hasPrefix(contentByte, "ID3") || hasPrefix(contentByte, "\xff\xfb") || hasPrefix(contentByte, "\xff\xf3") || hasPrefix(contentByte, "\xff\xf2")):
		return "MP3 audio file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x00\x00\x00\x20\x66\x74\x79\x70") || hasPrefix(contentByte, "\x00\x00\x00\x18\x66\x74\x79\x70") || hasPrefix(contentByte, "\x00\x00\x00\x14\x66\x74\x79\x70")):
		return "MP4 video file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x52\x61\x72\x21\x1A\x07\x01\x00")):
		return "RAR archive data"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x37\x7A\xBC\xAF\x27\x1C")):
		return "7zip archive data"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x00\x00\x01\x00")):
		return "MS Windows icon resource"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")):
		return "SQLite database"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x0A\x0D\x0D\x0A")):
		return "PCAP-ng capture file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\xD4\xC3\xB2\xA1") || hasPrefix(contentByte, "\xA1\xB2\xC3\xD4") || hasPrefix(contentByte, "\x4D\x3C\xB2\xA1") || hasPrefix(contentByte, "\xA1\xB2\x3C\x4D")):
		return "PCAP capture file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x66\x4C\x61\x43")):
		return "FLAC audio format"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x54\x44\x46\x24")):
		return "Telegram Desktop file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x54\x44\x45\x46")):
		return "Telegram Desktop encrypted file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x4D\x53\x43\x46")):
		return "Microsoft Cabinet file"
	case lenb > 16 &&
		(hasPrefix(contentByte, "\x38\x42\x50\x53")):
		return "Photoshop document"
	case lenb > 32 && hasPrefix(contentByte, "RIF") &&
		equal(contentByte[8:11], "AVI"):
		return "AVI file"
	case lenb > 32 && hasPrefix(contentByte, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
		return "Microsoft Office (Legacy format)"
	case lenb > 32 && hasPrefix(contentByte, "RIF") &&
		equal(contentByte[8:12], "WEBP"):
		return "Google Webp file"
	case lenb > 32 && hasPrefix(contentByte, "\x7B\x5C\x72\x74\x66\x31"):
		return "Rich Text Format"
	case lenb > 32 && (hasPrefix(contentByte, "<!DOCTYPE html") || hasPrefix(contentByte, "<head>")):
		return "HTML document"
	case lenb > 32 && hasPrefix(contentByte, "<?xml version"):
		return "XML document"
	case lenb > 32 && hasPrefix(contentByte, "<svg"):
		return "SVG image data"
	}
	return "Unknown file type"
}

func doElf(contentByte []byte) string {
	bits := int(contentByte[4])
	endian := contentByte[5]

	var elfint func(c []byte, size int) int

	if endian == 2 {
		elfint = peekBe
	} else {
		elfint = peekLe
	}

	exei := elfint(contentByte[16:], 2)

	var result string
	switch exei {
	case 1:
		result = "relocatable"
	case 2:
		result = "executable"
	case 3:
		result = "shared object"
	case 4:
		result = "core dump"
	default:
		result = "bad type"
	}

	result += ", "

	switch bits {
	case 1:
		result += "32-bit "
	case 2:
		result += "64-bit "
	}

	switch endian {
	case 1:
		result += "LSB "
	case 2:
		result += "MSB "
	default:
		result += "bad endian "
	}

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
			result += key
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
			result += ", dynamically linked"
		}
	}

	if !dynamic {
		result += ", statically linked"
	}

	return result
}

func peExecutable(contentByte []byte, magic int) string {
	var result string
	if peekLe(contentByte[magic+24:], 2) == 0x20b {
		result += "+"
	}
	result += " executable"
	if peekLe(contentByte[magic+22:], 2)&0x2000 != 0 {
		result += "(DLL) "
	}
	result += " "
	if peekLe(contentByte[magic+20:], 2) > 70 {
		types := []string{"", "native", "GUI", "console", "OS/2", "driver", "CE",
			"EFI", "EFI boot", "EFI runtime", "EFI ROM", "XBOX", "", "boot"}
		tp := peekLe(contentByte[magic+92:], 2)
		if tp > 0 && tp < len(types) {
			result += types[tp]
		} else {
			result += "unknown"
		}
	}

	// Ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
	switch peekLe(contentByte[magic+4:], 2) {
	case 0x1c0:
		result += " arm"
	case 0xaa64:
		result += " aarch64"
	case 0x14c:
		result += " Intel 80386"
	case 0x8664:
		result += " amd64"
	}
	return result
}
