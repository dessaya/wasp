package actorstest

import (
	"github.com/iotaledger/wasp/v2/packages/actors"
)

// Silent is an actor that drops all incoming messages and never produces any output.
type Silent struct {
	actors.Actor
	endpoint *actors.Endpoint
}

func NewSilent(endpoint *actors.Endpoint) *Silent {
	return &Silent{
		Actor:    actors.NewActor(endpoint),
		endpoint: endpoint,
	}
}

func (s *Silent) Run() {
	s.Go(func() {
		for {
			s.endpoint.Receive(nil)
		}
	})
}
