package proxy

import (
	"container/list"
	"sync"
)

// lruEntry stores a key-value pair for the LRU cache list element.
type lruEntry[V any] struct {
	key string
	val V
}

// lruCache is a thread-safe generic LRU cache implemented using
// container/list and a map with no external dependencies.
type lruCache[V any] struct {
	maxSize int
	items   map[string]*list.Element
	order   *list.List
	mu      sync.Mutex
}

// newLRUCache creates a new LRU cache with the given maximum size.
func newLRUCache[V any](maxSize int) *lruCache[V] {
	return &lruCache[V]{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

// Get retrieves a value from the cache by key. If found, the entry
// is promoted to the front of the LRU list (most recently used).
func (c *lruCache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*lruEntry[V]).val, true
	}
	var zero V
	return zero, false
}

// Put adds a value to the cache. If the key already exists, the entry is
// updated and promoted. If the cache is at capacity, the least recently used
// entry is evicted.
func (c *lruCache[V]) Put(key string, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		elem.Value.(*lruEntry[V]).val = val
		return
	}

	if c.order.Len() >= c.maxSize {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*lruEntry[V]).key)
		}
	}

	entry := &lruEntry[V]{key: key, val: val}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
}

// GetOrCreate retrieves the value for key, or atomically creates and inserts
// one using the provided function if the key is absent. This avoids the TOCTOU
// race of separate Get + Put calls where two goroutines could each create a
// value for the same key.
func (c *lruCache[V]) GetOrCreate(key string, create func() V) V {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*lruEntry[V]).val
	}

	val := create()

	if c.order.Len() >= c.maxSize {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*lruEntry[V]).key)
		}
	}

	entry := &lruEntry[V]{key: key, val: val}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
	return val
}

// Len returns the number of entries in the cache.
func (c *lruCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
