package actors

import (
	"log/slog"
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/iotaledger/wasp/v2/packages/cryptolib"
)

// NodeID is the unique identifier of a node in the network.
type NodeID [32]byte

func (id NodeID) String() string {
	return hexutil.Encode(id[:])
}

func (id NodeID) ShortString() string {
	return hexutil.Encode(id[:4])
}

func NodeIDFromPublicKey(pk *cryptolib.PublicKey) NodeID {
	var nodeID NodeID
	copy(nodeID[:], pk.AsBytes())
	return nodeID
}

// Router coordinates the actors within a node.
type Router struct {
	// Me identifies the node in the network
	Me NodeID
	// Peers is the list of all peers in the network (including Me)
	Peers []NodeID
	// mu protects open & closed
	mu sync.RWMutex
	// endpoints is the set of currently active endpoints
	endpoints map[Path]*Endpoint
	// out is the channel that delivers outgoing messages from all endpoints
	out chan MessageOutWithPath
	// ctx is the context for managing goroutines
	ctx *Context
}

func NewRouter(ctx *Context, me NodeID, peers []NodeID) *Router {
	return &Router{
		Me:        me,
		Peers:     peers,
		endpoints: make(map[Path]*Endpoint),
		out:       make(chan MessageOutWithPath),
		ctx:       ctx,
	}
}

func (r *Router) Context() *Context {
	return r.ctx
}

// GetEndpoint returns the Endpoint for the given Path, creating it if necessary.
func (r *Router) GetEndpoint(path Path) *Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	if endpoint := r.endpoints[path]; endpoint != nil {
		return endpoint
	}
	endpoint := NewEndpoint(r, path)
	r.endpoints[path] = endpoint
	r.ctx.Wg.Go(func() { r.endpointWorker(endpoint) })
	return endpoint
}

// endpointWorker forwards outgoing messages from the endpoint to the router's out channel.
func (r *Router) endpointWorker(endpoint *Endpoint) {
	for {
		select {
		case <-r.ctx.Done():
			return
		case msg := <-endpoint.out:
			select {
			case <-r.ctx.Done():
				return
			case r.out <- MessageOutWithPath{
				MessageOut: msg,
				Path:       endpoint.Path,
			}:
			}
		}
	}
}

// Out returns the channel for collecting outgoing messages from all endpoints.
func (r *Router) Out() <-chan MessageOutWithPath {
	return r.out
}

func (r *Router) LogStatus() {
	for _, endpoint := range r.endpoints {
		endpoint.LogStatus()
	}
}

func (r *Router) Log() *slog.Logger {
	return r.Context().Log().With("nodeID", r.Me.ShortString())
}
