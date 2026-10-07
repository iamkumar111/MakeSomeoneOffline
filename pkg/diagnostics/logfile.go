// Package diagnostics retains bounded troubleshooting logs across restarts.
package diagnostics

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type LogFile struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	size     int64
	maxBytes int64
	backups  int
}

func OpenLog(dir string, maxBytes int64, backups int) (*LogFile, error) {
	if maxBytes <= 0 || backups < 1 {
		return nil, fmt.Errorf("invalid log retention limits")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	w := &LogFile{path: filepath.Join(dir, "control-plane.log"), maxBytes: maxBytes, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *LogFile) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file, w.size = f, info.Size()
	return nil
}

func (w *LogFile) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	// Fixed application-owned filenames only; never delete a directory.
	for i := w.backups; i >= 1; i-- {
		destination := fmt.Sprintf("%s.%d", w.path, i)
		if i == w.backups {
			if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		source := w.path
		if i > 1 {
			source = fmt.Sprintf("%s.%d", w.path, i-1)
		}
		if err := os.Rename(source, destination); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return w.open()
}

func (w *LogFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *LogFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// ConsoleAndFile keeps console output even if writing the file fails.
type ConsoleAndFile struct {
	Console io.Writer
	File    io.Writer
}

func (w ConsoleAndFile) Write(p []byte) (int, error) {
	n, err := w.Console.Write(p)
	if _, fileErr := w.File.Write(p); fileErr != nil {
		fmt.Fprintf(w.Console, "Troubleshooting log write failed: %v\n", fileErr)
	}
	return n, err
}
