package actors

import (
	"context"
)

// Context represents the context for one or more actors and their goroutines.
type Context struct {
	context.Context
	Cancel func()
	Wg     *WaitGroup
}

func NewContext(ctx context.Context, onRecover func(any)) *Context {
	ctx, cancel := context.WithCancel(ctx)
	return &Context{
		Context: ctx,
		Cancel:  cancel,
		Wg:      NewWaitGroup(onRecover),
	}
}
