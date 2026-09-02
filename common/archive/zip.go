package archive

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

// ExtractZIP extracts all files in a ZIP archive into an existing directory safely.
func ExtractZIP(ctx context.Context, reader *zip.Reader, directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	trimDir := zipIsInSingleDirectory(reader.File)
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if trimDir {
			pathElements = pathElements[1:]
		}
		if len(pathElements) == 0 {
			continue
		}
		entryPath := filepath.Join(pathElements...)
		err = extractZIPEntry(ctx, root, directory, file, entryPath)
		if err != nil {
			return E.Cause(err, "extract ZIP entry: ", file.Name)
		}
	}
	return nil
}

func extractZIPEntry(ctx context.Context, root *os.Root, directory string, file *zip.File, entryPath string) error {
	err := mkdirAll(ctx, root, directory, filepath.Dir(entryPath))
	if err != nil {
		return err
	}
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	writer, err := root.Create(entryPath)
	if err != nil {
		return err
	}
	defer writer.Close()
	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}
	return filemanager.Chown(ctx, filepath.Join(directory, entryPath))
}

func mkdirAll(ctx context.Context, root *os.Root, directory string, path string) error {
	if path == "." {
		return nil
	}
	var current string
	for element := range strings.SplitSeq(path, string(filepath.Separator)) {
		current = filepath.Join(current, element)
		err := root.Mkdir(current, 0o755)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return err
		}
		err = filemanager.Chown(ctx, filepath.Join(directory, current))
		if err != nil {
			return err
		}
	}
	return nil
}

func zipIsInSingleDirectory(files []*zip.File) bool {
	var dirName string
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		pathElements := strings.Split(file.Name, "/")
		if len(pathElements) < 2 {
			return false
		}
		if dirName == "" {
			dirName = pathElements[0]
		} else if dirName != pathElements[0] {
			return false
		}
	}
	return dirName != ""
}
