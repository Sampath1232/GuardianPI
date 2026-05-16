// Guardian Pi — Disk-backed Offline Queue
// Persists telemetry events to disk when server is unreachable.
package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DiskQueue provides a simple file-backed FIFO queue
type DiskQueue struct {
	dir           string
	maxSizeMB     int
	mu            sync.Mutex
}

// NewDiskQueue creates a new disk-backed queue
func NewDiskQueue(dir string, maxSizeMB int) *DiskQueue {
	os.MkdirAll(dir, 0700)
	return &DiskQueue{dir: dir, maxSizeMB: maxSizeMB}
}

// Enqueue writes data to a new file in the queue directory
func (q *DiskQueue) Enqueue(data []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Enforce max size
	q.enforceLimit()

	filename := fmt.Sprintf("%d.gpi", time.Now().UnixNano())
	path := filepath.Join(q.dir, filename)
	return os.WriteFile(path, data, 0600)
}

// Dequeue reads and removes the oldest file from the queue
func (q *DiskQueue) Dequeue() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	files, err := q.listFiles()
	if err != nil || len(files) == 0 {
		return nil, false
	}

	path := filepath.Join(q.dir, files[0])
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	os.Remove(path)
	return data, true
}

// Size returns the number of queued items
func (q *DiskQueue) Size() int {
	files, _ := q.listFiles()
	return len(files)
}

func (q *DiskQueue) listFiles() ([]string, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".gpi" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (q *DiskQueue) enforceLimit() {
	var totalSize int64
	entries, _ := os.ReadDir(q.dir)
	for _, e := range entries {
		info, _ := e.Info()
		if info != nil {
			totalSize += info.Size()
		}
	}

	maxBytes := int64(q.maxSizeMB) * 1024 * 1024
	if totalSize <= maxBytes {
		return
	}

	// Remove oldest files until under limit
	files, _ := q.listFiles()
	for _, f := range files {
		if totalSize <= maxBytes {
			break
		}
		path := filepath.Join(q.dir, f)
		info, _ := os.Stat(path)
		if info != nil {
			totalSize -= info.Size()
		}
		os.Remove(path)
	}
}
