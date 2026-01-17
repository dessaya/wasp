package actors

import (
	"context"

	"github.com/samber/lo"
)

// Future represents a value that will be available some time in the future.
type Future[T any] struct {
	ready chan struct{}
	value T
}

// NewFuture creates a new Future.
func NewFuture[T any]() *Future[T] {
	f := &Future[T]{
		ready: make(chan struct{}),
	}
	return f
}

// Set sets the value of the future and marks it as ready.
// Set should only be called once.
func (f *Future[T]) Set(value T) {
	if f.IsReady() {
		panic("future already set")
	}
	f.value = value
	close(f.ready)
}

// Get blocks until the future is ready or the context is done.
func (f *Future[T]) Get(ctx context.Context) (T, error) {
	var zero T
	select {
	case <-f.ready:
		return f.value, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (f *Future[T]) MustGet() T {
	if !f.IsReady() {
		panic("future not ready")
	}
	return f.value
}

// IsReady returns true if the future is ready.
func (f *Future[T]) IsReady() bool {
	select {
	case <-f.ready:
		return true
	default:
		return false
	}
}

// ValueChan returns a channel that will receive the value when it is ready.
func (f *Future[T]) ValueChan() <-chan T {
	ch := make(chan T, 1)
	go func() {
		<-f.ready
		ch <- f.value
		close(ch)
	}()
	return ch
}

// ReadyChan returns a channel that will be closed when the future is ready.
func (f *Future[T]) ReadyChan() <-chan struct{} {
	return f.ready
}

func WaitAll[T any](ctx context.Context, futs []*Future[T]) error {
	for _, f := range futs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.ReadyChan():
		}
	}
	return nil
}

// JoinFutures returns a channel that will receive the results of all the given futures.
// The results are sent in the order the futures are provided, with their index.
func JoinFutures[T any](futs []*Future[T]) <-chan lo.Tuple2[int, T] {
	ch := make(chan lo.Tuple2[int, T], len(futs))
	for i, f := range futs {
		go func() {
			v := <-f.ValueChan()
			ch <- lo.T2(i, v)
		}()
	}
	return ch
}
