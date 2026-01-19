package actors

import (
	"log/slog"
)

type Actor[T any] interface {
	Endpoint() *Endpoint
	Output() *Future[T]
	Log() *slog.Logger
	SetOutput(value T)
	Context() *Context
	Go(func())
}

func NewActor[T any](endpoint *Endpoint, log *slog.Logger) *actor[T] {
	return &actor[T]{
		endpoint: endpoint,
		output:   NewFuture[T](),
		log:      log.With("actor", endpoint.Path),
	}
}

type actor[T any] struct {
	endpoint *Endpoint
	output   *Future[T]
	log      *slog.Logger
}

func (a *actor[T]) Endpoint() *Endpoint {
	return a.endpoint
}

func (a *actor[T]) Output() *Future[T] {
	return a.output
}

func (a *actor[T]) Log() *slog.Logger {
	return a.log
}

func (a *actor[T]) SetOutput(value T) {
	a.output.Set(value)
}

func WaitOutput[S any](ctx *Context, sub Actor[S]) (output S) {
	select {
	case <-ctx.Done():
		panic(ctx.Err())
	case output = <-sub.Output().ValueChan(ctx):
		return output
	}
}

func (a *actor[T]) Context() *Context {
	return a.Endpoint().Context()
}

func (a *actor[T]) Go(f func()) {
	a.Context().Wg.Go(f)
}
