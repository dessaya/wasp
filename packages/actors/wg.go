package actors

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// The code in this file is adapted from github.com/sourcegraph/conc

// NewWaitGroup creates a new WaitGroup.
func NewWaitGroup(onRecover func(any)) *WaitGroup {
	return &WaitGroup{onRecover: onRecover}
}

// WaitGroup is the primary building block for scoped concurrency.
// Goroutines can be spawned in the WaitGroup with the Go method,
// and calling Wait() will ensure that each of those goroutines exits
// before continuing. Any panics in a child goroutine will be caught
// and propagated to the caller of Wait().
//
// The zero value of WaitGroup is usable, just like sync.WaitGroup.
// Also like sync.WaitGroup, it must not be copied after first use.
type WaitGroup struct {
	wg        sync.WaitGroup
	pc        Catcher
	onRecover func(any)
}

// Go spawns a new goroutine in the WaitGroup.
func (h *WaitGroup) Go(f func()) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.pc.Try(f, h.onRecover)
	}()
}

// Wait will block until all goroutines spawned with Go exit and will
// propagate any panics spawned in a child goroutine.
func (h *WaitGroup) Wait() {
	h.wg.Wait()

	// Propagate a panic if we caught one from a child goroutine.
	h.pc.Repanic()
}

// WaitAndRecover will block until all goroutines spawned with Go exit and
// will return a *panics.Recovered if one of the child goroutines panics.
func (h *WaitGroup) WaitAndRecover() *Recovered {
	h.wg.Wait()

	return h.pc.Recovered()
}

// Catcher is used to catch panics. You can execute a function with Try,
// which will catch any spawned panic. Try can be called any number of times,
// from any number of goroutines. Once all calls to Try have completed, you can
// get the value of the first panic (if any) with Recovered(), or you can just
// propagate the panic (re-panic) with Repanic().
type Catcher struct {
	recovered atomic.Pointer[Recovered]
}

// Try executes f, catching any panic it might spawn. It is safe
// to call from multiple goroutines simultaneously.
func (p *Catcher) Try(f func(), onRecover func(any)) {
	defer p.tryRecover(onRecover)
	f()
}

func isError(val any) bool {
	if err, ok := val.(error); ok {
		if errors.Is(err, context.Canceled) {
			return false
		}
	}
	return true
}

func (p *Catcher) tryRecover(onRecover func(any)) {
	if val := recover(); val != nil && isError(val) {
		onRecover(val)
		rp := NewRecovered(1, val)
		p.recovered.CompareAndSwap(nil, &rp)
	}
}

// Repanic panics if any calls to Try caught a panic. It will panic with the
// value of the first panic caught, wrapped in a panics.Recovered with caller
// information.
func (p *Catcher) Repanic() {
	if val := p.Recovered(); val != nil && isError(val) {
		panic(val)
	}
}

// Recovered returns the value of the first panic caught by Try, or nil if
// no calls to Try panicked.
func (p *Catcher) Recovered() *Recovered {
	return p.recovered.Load()
}

// NewRecovered creates a panics.Recovered from a panic value and a collected
// stacktrace. The skip parameter allows the caller to skip stack frames when
// collecting the stacktrace. Calling with a skip of 0 means include the call to
// NewRecovered in the stacktrace.
func NewRecovered(skip int, value any) Recovered {
	// 64 frames should be plenty
	var callers [64]uintptr
	n := runtime.Callers(skip+1, callers[:])
	return Recovered{
		Value:   value,
		Callers: callers[:n],
		Stack:   debug.Stack(),
	}
}

// Recovered is a panic that was caught with recover().
type Recovered struct {
	// The original value of the panic.
	Value any
	// The caller list as returned by runtime.Callers when the panic was
	// recovered. Can be used to produce a more detailed stack information with
	// runtime.CallersFrames.
	Callers []uintptr
	// The formatted stacktrace from the goroutine where the panic was recovered.
	// Easier to use than Callers.
	Stack []byte
}

// String renders a human-readable formatting of the panic.
func (p *Recovered) String() string {
	return fmt.Sprintf("panic: %v\nstacktrace:\n%s\n", p.Value, p.Stack)
}

// AsError casts the panic into an error implementation. The implementation
// is unwrappable with the cause of the panic, if the panic was provided one.
func (p *Recovered) AsError() error {
	if p == nil {
		return nil
	}
	return &ErrRecovered{*p}
}

// ErrRecovered wraps a panics.Recovered in an error implementation.
type ErrRecovered struct{ Recovered }

var _ error = (*ErrRecovered)(nil)

func (p *ErrRecovered) Error() string { return p.String() }

func (p *ErrRecovered) Unwrap() error {
	if err, ok := p.Value.(error); ok {
		return err
	}
	return nil
}
