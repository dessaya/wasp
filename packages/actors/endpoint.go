package actors

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// NodeID is the unique identifier of a node in the network.
type NodeID [32]byte

func (id NodeID) String() string {
	return hexutil.Encode(id[:])
}

func (id NodeID) ShortString() string {
	return hexutil.Encode(id[:4])
}

// Path is a unique name for each actor in a node. An actor can only communicate
// with other actors with the same Path in other nodes.
type Path string

func (p Path) Sub(format string, args ...any) Path {
	return p + "/" + Path(fmt.Sprintf(format, args...))
}

// An Endpoint represents the communication endpoint for an actor in a node.
// An actor is any component that implements some kind of distributed algorithm.
// Each actor is associated with an Endpoint for communicating with other
// actors with the same Path in other nodes.
type Endpoint struct {
	Router *Router
	// Path is a unique identifier of the actor within a node.
	Path Path
	// in is the channel for incoming messages to the actor. Received messages
	// are always from an actor with the same Path.
	in chan MessageIn
	// out is the channel for outgoing messages from the actor. Sent messages
	// are always to an actor with the same Path.
	out chan MessageOut
}

func NewEndpoint(router *Router, path Path) *Endpoint {
	bufSize := 10 * len(router.Peers)
	return &Endpoint{
		Router: router,
		Path:   path,
		in:     make(chan MessageIn, bufSize),
		out:    make(chan MessageOut, bufSize),
	}
}

func (e *Endpoint) Context() *Context {
	return e.Router.Context()
}

func (e *Endpoint) N() int {
	return len(e.Router.Peers)
}

func (e *Endpoint) Me() NodeID {
	return e.Router.Me
}

// In is to be used for delivering messages to the node
func (e *Endpoint) In() chan<- MessageIn {
	return e.in
}

// Out is to be used for collecting outgoing messages from the node
func (e *Endpoint) Out() <-chan MessageOut {
	return e.out
}

// Receive receives a message for the actor, blocking until a message is available or the context is done.
func (e *Endpoint) Receive() MessageIn {
	ctx := e.Context()
	select {
	case <-ctx.Done():
		panic(ctx.Err())
	case msg, ok := <-e.in:
		if !ok {
			panic(context.Canceled)
		}
		return msg
	}
}

// Send sends a message to a peer
func (e *Endpoint) Send(peer NodeID, m MessagePayload) {
	ctx := e.Context()
	select {
	case <-ctx.Done():
		panic(ctx.Err())
	case e.out <- NewMessageOut(peer, m):
	default:
		panic(errors.New("cannot send message: endpoint out channel full"))
	}
}

// SendToAll sends a message to all peers
func (e *Endpoint) SendToAll(m MessagePayload) {
	for _, peer := range e.Router.Peers {
		e.Send(peer, m)
	}
}

func (e *Endpoint) SendToAllButMe(m MessagePayload) {
	for _, peer := range e.Router.Peers {
		if peer != e.Router.Me {
			e.Send(peer, m)
		}
	}
}

func (e *Endpoint) Sub(subpath string, args ...any) *Endpoint {
	return e.Router.GetEndpoint(e.Path.Sub(subpath, args...))
}
