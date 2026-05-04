package authz

import "sync"

type ResourceExtractor func(req any) Resource

type ResourceMap struct {
	mu         sync.RWMutex
	extractors map[string]ResourceExtractor
}

func NewResourceMap() *ResourceMap {
	return &ResourceMap{extractors: make(map[string]ResourceExtractor)}
}

func (m *ResourceMap) Register(fullMethod string, extractor ResourceExtractor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extractors[fullMethod] = extractor
}

func (m *ResourceMap) Extract(fullMethod string, req any) Resource {
	m.mu.RLock()
	fn, ok := m.extractors[fullMethod]
	m.mu.RUnlock()
	if !ok {
		return ThisNode()
	}
	return fn(req)
}
