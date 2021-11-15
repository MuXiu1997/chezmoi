package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// An Format is an archive format and implements the
// github.com/spf13/pflag.Value interface.
type Format string

// Archive formats.
const (
	FormatUnknown Format = ""
	FormatTar     Format = "tar"
	FormatTarBz2  Format = "tar.bz2"
	FormatTarGz   Format = "tar.gz"
	FormatTbz2    Format = "tbz2"
	FormatTgz     Format = "tgz"
	FormatZip     Format = "zip"
)

var Stop = io.EOF

type InvalidFormatError string

func (e InvalidFormatError) Error() string {
	if e == InvalidFormatError(FormatUnknown) {
		return "invalid archive format"
	}
	return fmt.Sprintf("%s: invalid archive format", string(e))
}

// An WalkArchiveFunc is called once for each entry in an archive.
type WalkArchiveFunc func(name string, info fs.FileInfo, r io.Reader, linkname string) error

// Set implements github.com/spf13/pflag.Value.Set.
func (f *Format) Set(s string) error {
	*f = Format(s)
	return nil
}

// String implements github.com/spf13/pflag.Value.String.
func (f Format) String() string {
	return string(f)
}

// Type implements github.com/spf13/pflag.Value.Type.
func (f Format) Type() string {
	return "format"
}

// GuessFormat guesses the archive format from the path and data.
func GuessFormat(path string, data []byte) Format {
	switch pathLower := strings.ToLower(path); {
	case strings.HasSuffix(pathLower, ".tar"):
		return FormatTar
	case strings.HasSuffix(pathLower, ".tar.bz2") || strings.HasSuffix(pathLower, ".tbz2"):
		return FormatTarBz2
	case strings.HasSuffix(pathLower, ".tar.gz") || strings.HasSuffix(pathLower, ".tgz"):
		return FormatTarGz
	case strings.HasSuffix(pathLower, ".zip"):
		return FormatZip
	}

	switch {
	case len(data) >= 3 && bytes.Equal(data[:3], []byte{0x1f, 0x8b, 0x08}):
		return FormatTarGz
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}):
		return FormatZip
	case isTar(bytes.NewReader(data)):
		return FormatTar
	case isTar(bzip2.NewReader(bytes.NewReader(data))):
		return FormatTarBz2
	}

	return FormatUnknown
}

// Walk walks over all the entries in an archive.
func Walk(data []byte, format Format, f WalkArchiveFunc) error {
	if format == FormatZip {
		return walkZip(bytes.NewReader(data), int64(len(data)), f)
	}
	var r io.Reader = bytes.NewReader(data)
	switch format {
	case FormatTar:
	case FormatTarBz2, FormatTbz2:
		r = bzip2.NewReader(r)
	case FormatTarGz, FormatTgz:
		var err error
		r, err = gzip.NewReader(r)
		if err != nil {
			return err
		}
	default:
		return InvalidFormatError(format)
	}
	return walkTar(r, f)
}

// isTar returns if r looks like a tar archive.
func isTar(r io.Reader) bool {
	tarReader := tar.NewReader(r)
	_, err := tarReader.Next()
	return err == nil
}

// walkTar walks over all the entries in a tar archive.
func walkTar(r io.Reader, f WalkArchiveFunc) error {
	tarReader := tar.NewReader(r)
	for {
		header, err := tarReader.Next()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}
		name := strings.TrimSuffix(header.Name, "/")
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeReg:
			switch err := f(name, header.FileInfo(), tarReader, ""); {
			case errors.Is(err, Stop):
				return nil
			case err != nil:
				return err
			}
		case tar.TypeSymlink:
			switch err := f(name, header.FileInfo(), nil, header.Linkname); {
			case errors.Is(err, Stop):
				return nil
			case err != nil:
				return err
			}
		case tar.TypeXGlobalHeader:
		default:
			return fmt.Errorf("%s: unsupported typeflag '%c'", header.Name, header.Typeflag)
		}
	}
}

// walkZip walks over all the entries in a zip archive.
func walkZip(r io.ReaderAt, size int64, f WalkArchiveFunc) error {
	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		return err
	}
	for _, zipFile := range zipReader.File {
		zipFileReader, err := zipFile.Open()
		if err != nil {
			return err
		}
		name := path.Clean(zipFile.Name)
		if strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
			return fmt.Errorf("%s: invalid filename", zipFile.Name)
		}
		err = f(name, zipFile.FileInfo(), zipFileReader, "")
		zipFileReader.Close()
		switch {
		case errors.Is(err, Stop):
			return nil
		case err != nil:
			return err
		}
	}
	return nil
}
