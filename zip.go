package fileident

import (
	"archive/zip"
	"os"
	"strings"
)

func doZip(file *os.File) string {
	info, err := file.Stat()
	if err != nil {
		return "file error: " + err.Error()
	}

	var buf [60]byte
	_, err = file.Read(buf[:])
	if err != nil {
		return "file error: " + err.Error()
	}

	str := string(buf[:])

	switch {
	case strings.Contains(str, "word/") && strings.Contains(str, "xml"):
		return "Microsoft Word 2007+"
	case strings.Contains(str, "ppt/theme"):
		return "Microsoft PowerPoint 2007+"
	case strings.Contains(str, "xl/") && strings.Contains(str, "xml"):
		return "Microsoft Excel 2007+"
	default:
		f, err := os.Open(file.Name())
		if err != nil {
			return "error opening file: " + err.Error()
		}
		defer f.Close()

		zipReader, err := zip.NewReader(f, info.Size())
		if err != nil {
			return "unknown file type"
		}

		for _, zipFile := range zipReader.File {
			switch zipFile.Name {
			case "word/document.xml":
				return "Microsoft Word 2007+"
			case "xl/workbook.xml":
				return "Microsoft Excel 2007+"
			case "ppt/presentation.xml":
				return "Microsoft PowerPoint 2007+"
			case "mimetype":
				file, err := zipFile.Open()
				if err != nil {
					return "error opening file: " + err.Error()
				}
				defer file.Close()
				first20Bytes := make([]byte, 20)
				_, err = file.Read(first20Bytes)
				if err != nil {
					return "error reading first 20 bytes: " + err.Error()
				}
				if strings.Contains(string(first20Bytes), "epub") {
					return "EPUB document"
				}
			}
		}
	}

	return "Zip archive data"
}
