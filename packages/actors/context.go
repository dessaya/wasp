package actors

import (
	"context"
	"log/slog"
)

// Context represents the context for one or more actors and their goroutines.
type Context struct {
	context.Context
	Cancel func()
	Wg     *WaitGroup
	log    *slog.Logger
}

func NewContext(ctx context.Context, onRecover func(any), log *slog.Logger) *Context {
	ctx, cancel := context.WithCancel(ctx)
	return &Context{
		Context: ctx,
		Cancel:  cancel,
		Wg:      NewWaitGroup(onRecover),
		log:     log,
	}
}

func (c *Context) Log() *slog.Logger {
	return c.log
}
