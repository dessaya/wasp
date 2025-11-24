package actors

import (
	"context"
	"sync"
)

// Router coordinates the actors within a node.
type Router struct {
	// Me identifies the node in the network
	Me NodeID
	// Peers is the list of all peers in the network (including Me)
	Peers []NodeID
	// mu protects open & closed
	mu sync.RWMutex
	// open is the set of currently active endpoints
	open map[Path]*Endpoint
	// closed is the set of closed endpoints (which might still receive
	// messages from other nodes)
	closed map[Path]*Endpoint
	// out is the channel that delivers outgoing messages from all endpoints
	out chan MessageOutWithPath
	// ctx is the context for managing goroutines
	ctx context.Context
}

func NewRouter(ctx context.Context, me NodeID, peers []NodeID) *Router {
	return &Router{
		Me:     me,
		Peers:  peers,
		open:   make(map[Path]*Endpoint),
		closed: make(map[Path]*Endpoint),
		out:    make(chan MessageOutWithPath),
		ctx:    ctx,
	}
}

// GetEndpoint returns the Endpoint for the given Path, creating it if necessary.
func (r *Router) GetEndpoint(path Path) *Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	if endpoint := r.closed[path]; endpoint != nil {
		return endpoint
	}
	if endpoint := r.open[path]; endpoint != nil {
		return endpoint
	}
	endpoint := NewEndpoint(r, path)
	r.open[path] = endpoint
	go r.endpointWorker(endpoint)
	return endpoint
}

// endpointWorker forwards outgoing messages from the endpoint to the router's out channel.
func (r *Router) endpointWorker(endpoint *Endpoint) {
	for msg := range endpoint.out {
		select {
		case r.out <- MessageOutWithPath{
			MessageOut: msg,
			Path:       endpoint.Path,
		}:
		case <-r.ctx.Done():
			return
		}
	}
	r.mu.Lock()
	delete(r.open, endpoint.Path)
	r.closed[endpoint.Path] = endpoint
	if len(r.open) == 0 {
		close(r.out)
	}
	r.mu.Unlock()
}

// Out returns the channel for collecting outgoing messages from all endpoints.
func (r *Router) Out() <-chan MessageOutWithPath {
	return r.out
}
