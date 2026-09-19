package main

import (
	"container/list"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// This is a memory budget, never an inspection/read budget. Eviction only means
// a later request reads again. Different read policies cannot share prefixes.
const contentCacheBytes = 32 << 20

type cachedContent struct {
	path   string
	source bool
	info   os.FileInfo
	data   []byte
}
type contentCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
	bytes   int
}

func newContentCache() *contentCache {
	return &contentCache{entries: map[string]*list.Element{}, order: list.New()}
}
func sameFileVersion(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime() == b.ModTime() && a.Mode() == b.Mode()
}
func (c *contentCache) get(path string, source bool, info os.FileInfo) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[path]
	if e == nil {
		return nil, false
	}
	value := e.Value.(cachedContent)
	if value.source != source || !sameFileVersion(value.info, info) {
		return nil, false
	}
	c.order.MoveToFront(e)
	return value.data, true
}
func (c *contentCache) put(path string, source bool, info os.FileInfo, data []byte) {
	if c == nil || info == nil || data == nil || len(data) > contentCacheBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[path]; e != nil {
		c.remove(e)
	}
	for c.bytes+len(data) > contentCacheBytes {
		c.remove(c.order.Back())
	}
	c.entries[path] = c.order.PushFront(cachedContent{path, source, info, data})
	c.bytes += len(data)
}
func (c *contentCache) remove(e *list.Element) {
	value := e.Value.(cachedContent)
	delete(c.entries, value.path)
	c.bytes -= len(value.data)
	c.order.Remove(e)
}

func (s *Scanner) readCachedContent(f *os.File, path string, source bool, stats *contentReadStats) ([]byte, bool, error) {
	before, _ := f.Stat()
	if data, hit := s.reads.get(path, source, before); hit {
		s.debug.event("reuse-content", path, 0, 0)
		return data, false, nil
	}
	s.debug.event("read", path, 0, 0)
	data, binary, err := readScanContent(f, strings.ToLower(filepath.Ext(path)), source, stats, slices.ContainsFunc(KnownRepoPayloadHashes, func(h RepoPayloadHash) bool { return h.Filename == filepath.Base(path) }))
	after, _ := f.Stat()
	if err == nil && !binary && sameFileVersion(before, after) {
		s.reads.put(path, source, after, data)
	}
	return data, binary, err
}
