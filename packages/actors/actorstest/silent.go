package actorstest

import (
	"context"

	"github.com/iotaledger/wasp/v2/packages/actors"
)

// Silent is an actor that drops all incoming messages and never produces any output.
type Silent struct {
	endpoint *actors.Endpoint
}

func NewSilent(endpoint *actors.Endpoint) *Silent {
	return &Silent{
		endpoint: endpoint,
	}
}

func (s *Silent) Endpoint() *actors.Endpoint {
	return s.endpoint
}

func (s *Silent) Run(ctx context.Context) error {
	s.endpoint.Close()
	for {
		_, err := s.endpoint.Receive(ctx)
		if err != nil {
			return err
		}
	}
}
