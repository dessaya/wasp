package actors

import (
	"fmt"
)

// Output represents the output of an actor, which will be ready some time in the future.
type Output[T any] struct {
	ctx   *Context
	ready chan struct{}
	value T
}

// NewOutput creates a new Output.
func NewOutput[T any](ctx *Context) *Output[T] {
	return &Output[T]{
		ctx:   ctx,
		ready: make(chan struct{}),
	}
}

// OnReady registers a callback to be called when the output is ready.
func (o *Output[T]) OnReady(f func()) {
	o.ctx.Wg.Go(func() {
		o.WaitReady()
		f()
	})
}

// OnValueReady registers a callback to be called when the output is ready.
func (o *Output[T]) OnValueReady(f func(T)) {
	o.ctx.Wg.Go(func() {
		v := o.Wait()
		f(v)
	})
}

// WaitReady blocks until the output is ready.
func (o *Output[T]) WaitReady() {
	select {
	case <-o.ctx.Done():
		panic(o.ctx.Err())
	case <-o.ready:
	}
}

// Wait blocks until the output is ready and returns it.
func (o *Output[T]) Wait() T {
	select {
	case <-o.ctx.Done():
		panic(o.ctx.Err())
	case <-o.ready:
		return o.value
	}
}

// Set sets the value of the output and marks it as ready.
// Set should only be called once.
func (o *Output[T]) Set(value T) {
	if o.IsReady() {
		panic("output already set")
	}
	o.value = value
	close(o.ready)
}

// Get blocks until the output is ready or the context is done.
func (o *Output[T]) Get() (T, error) {
	select {
	case <-o.ready:
		return o.value, nil
	case <-o.ctx.Done():
		var zero T
		return zero, o.ctx.Err()
	}
}

func (o *Output[T]) MustGet() T {
	if !o.IsReady() {
		panic("output not ready")
	}
	return o.value
}

// IsReady returns true if the output is ready.
func (o *Output[T]) IsReady() bool {
	select {
	case <-o.ready:
		return true
	default:
		return false
	}
}

// ValueChan returns a channel that will receive the value when it is ready.
func (o *Output[T]) ValueChan() <-chan T {
	ch := make(chan T, 1)
	o.OnValueReady(func(v T) {
		ch <- v
	})
	return ch
}

// ReadyChan returns a channel that will be closed when the output is ready.
func (o *Output[T]) ReadyChan() <-chan struct{} {
	return o.ready
}

func (o *Output[T]) String() string {
	if o.IsReady() {
		return fmt.Sprintf("Output(%v)", o.value)
	}
	return "Output(<not ready>)"
}

func OutputsReadyChan[K comparable, T any](ctx *Context, outputs map[K]*Output[T]) chan K {
	ch := make(chan K, len(outputs))
	for k, out := range outputs {
		out.OnReady(func() {
			ch <- k
		})
	}
	return ch
}
