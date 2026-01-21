package actors

import (
	"log/slog"
)

type Actor interface {
	Endpoint() *Endpoint
	Context() *Context
	Go(func())
	Log() *slog.Logger
}

func NewActor(endpoint *Endpoint, log *slog.Logger) *actor {
	return &actor{
		endpoint: endpoint,
		log:      log.With("actor", endpoint.Path),
	}
}

type actor struct {
	endpoint *Endpoint
	log      *slog.Logger
}

func (a *actor) Endpoint() *Endpoint {
	return a.endpoint
}

func (a *actor) Log() *slog.Logger {
	return a.log
}

func (a *actor) Context() *Context {
	return a.Endpoint().Context()
}

func (a *actor) Go(f func()) {
	a.Context().Wg.Go(f)
}
