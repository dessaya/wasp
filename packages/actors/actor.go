package actors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

type Actor[T any] interface {
	Endpoint() *Endpoint
	Output() *Future[T]
	Errors() <-chan error
	Log() *slog.Logger
	LogError(err error)
	SetOutput(value T)
}

func NewActor[T any](endpoint *Endpoint, log *slog.Logger) *actor[T] {
	return &actor[T]{
		endpoint: endpoint,
		output:   NewFuture[T](),
		errors:   make(chan error),
		log:      log.With("actor", endpoint.Path),
	}
}

type actor[T any] struct {
	endpoint *Endpoint
	output   *Future[T]
	errors   chan error
	log      *slog.Logger
}

func (a *actor[T]) Endpoint() *Endpoint {
	return a.endpoint
}

func (a *actor[T]) Output() *Future[T] {
	return a.output
}

func (a *actor[T]) Errors() <-chan error {
	return a.errors
}

func (a *actor[T]) Log() *slog.Logger {
	return a.log
}

func (a *actor[T]) LogError(err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	a.log.Error(err.Error())
	select {
	case a.errors <- err:
	default:
		panic(fmt.Sprintf("error channel is full: %v", err))
	}
}

func (a *actor[T]) SetOutput(value T) {
	a.output.Set(value)
}

func WaitSubActor[T any, S any](ctx context.Context, parent Actor[T], sub Actor[S]) (output S, err error) {
	select {
	case <-ctx.Done():
		return output, ctx.Err()
	case err := <-sub.Errors():
		parent.LogError(fmt.Errorf("Error in subactor: %w", err))
		return output, err
	case output = <-sub.Output().ValueChan():
		return output, nil
	}
}
