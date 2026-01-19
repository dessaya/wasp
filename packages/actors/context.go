package actors

import (
	"context"

	"github.com/sourcegraph/conc"
)

// Context represents the context for one or more actors and their goroutines.
type Context struct {
	context.Context
	Cancel func()
	Wg     *conc.WaitGroup
}

func NewContext(ctx context.Context) *Context {
	ctx, cancel := context.WithCancel(ctx)
	wg := conc.NewWaitGroup()
	return &Context{
		Context: ctx,
		Cancel:  cancel,
		Wg:      wg,
	}
}
