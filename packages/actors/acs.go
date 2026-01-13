package actors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/samber/lo"
)

// ACS implements the Asynchronous Common Subset algorithm
// from the HBBFT paper:
//
// > Miller, A., Xia, Y., Croman, K., Shi, E., and Song, D. (2016). The Honey Badger of
// > BFT Protocols. In Proceedings of the 2016 ACM SIGSAC Conference on Computer
// > and Communications Security, CCS ’16, page 31–42, New York, NY, USA.
// > Association for Computing Machinery.
//
// The HBBFT paper presents the algorithm as follows:
//
// > Let {RBC_i}_N refer to N instances of the reliable broadcast protocol,
// > where P_i is the sender of RBC_i. Let {BA_i}_N refer to N instances
// > of the binary byzantine agreement protocol.
// >   • upon receiving input v_i, input v_i to RBC_i
// >   • upon delivery of v_j from RBC_j, if input has not yet been
// >     provided to BA_j, then provide input 1 to BA_j.
// >   • upon delivery of value 1 from at least N − f instances of BA,
// >     provide input 0 to each instance of BA that has not yet been
// >     provided input.
// >   • once all instances of BA have completed, let C ⊂ [1..N] be the
// >     indexes of each BA that delivered 1. Wait for the output v_j for
// >     each RBC_j such that j ∈ C. Finally output ∪_{j∈C} v_j.
type ACS struct {
	endpoint *Endpoint
	f        int
	makeCC   MakeCommonCoinFunc
	log      *slog.Logger
}

// Constructor.
func NewACS(
	endpoint *Endpoint,
	f int,
	makeCC MakeCommonCoinFunc,
	log *slog.Logger,
) *ACS {
	return &ACS{
		endpoint: endpoint,
		f:        f,
		makeCC:   makeCC,
		log:      log,
	}
}

func (a *ACS) Run(ctx context.Context, vi []byte) (map[NodeID][]byte, error) {
	defer a.endpoint.Close()

	// > Let {RBC_i}_N refer to N instances of the reliable broadcast protocol,
	// > where P_i is the sender of RBC_i.
	rbcs := make([]*ReliableBroadcast, a.endpoint.N())
	for i, nid := range a.endpoint.Router.Peers {
		rbcs[i] = NewReliableBroadcast(a.endpoint.Sub("rbc:%d", i), a.f, nid, a.log)
	}

	rbcResults := make([]*Future[Result[[]byte]], a.endpoint.N())
	for i, nid := range a.endpoint.Router.Peers {
		if nid == a.endpoint.Me() {
			// >   • upon receiving input v_i, input v_i to RBC_i
			rbcResults[i] = Run(func() ([]byte, error) {
				return rbcs[i].Broadcast(ctx, vi)
			})
		} else {
			rbcResults[i] = Run(func() ([]byte, error) {
				return rbcs[i].Receive(ctx)
			})
		}
	}
	rbcChan := JoinFutures(rbcResults)

	// > Let {BA_i}_N refer to N instances
	// > of the binary byzantine agreement protocol.
	abas := make([]*BinaryAgreement, a.endpoint.N())
	abaResults := make(map[int]bool)
	abaDone := make(chan error)
	makeABA := func(i int, input bool) {
		abas[i] = NewBinaryAgreement(a.endpoint.Sub("aba:%d", i), a.f, a.makeCC, a.log)
		go func() {
			abaOut, err := abas[i].Run(ctx, input)
			abaResults[i] = abaOut
			abaDone <- err
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case rbcRes := <-rbcChan:
			// >   • upon delivery of v_j from RBC_j, if input has not yet been
			// >     provided to BA_j, then provide input 1 to BA_j.
			j := rbcRes.A
			res := rbcRes.B
			if !res.IsOk() {
				return nil, fmt.Errorf("RBC failed: %w", rbcRes.B.Err)
			}
			a.log.Info("RBC done", "i", j)
			if abas[j] == nil {
				makeABA(j, true)
			}
		case err := <-abaDone:
			a.log.Info("ABA done", "amount", len(abaResults))
			// >   • upon delivery of value 1 from at least N − f instances of BA,
			// >     provide input 0 to each instance of BA that has not yet been
			// >     provided input.
			if err != nil {
				return nil, fmt.Errorf("ABA failed: %w", err)
			}
			if lo.Count(lo.Values(abaResults), true) == a.endpoint.N()-a.f {
				for i, aba := range abas {
					if aba == nil {
						makeABA(i, false)
					}
				}
			}
			// >   • once all instances of BA have completed, let C ⊂ [1..N] be the
			// >     indexes of each BA that delivered 1. Wait for the output v_j for
			// >     each RBC_j such that j ∈ C. Finally output ∪_{j∈C} v_j.
			if len(abaResults) == a.endpoint.N() {
				ret := make(map[NodeID][]byte)
				for i, val := range abaResults {
					if val {
						rbcRes, err := rbcResults[i].Get(ctx)
						if err != nil {
							return nil, fmt.Errorf("waiting for RBC result failed: %w", err)
						}
						if !rbcRes.IsOk() {
							return nil, fmt.Errorf("RBC failed: %w", rbcRes.Err)
						}
						ret[a.endpoint.Router.Peers[i]] = *rbcRes.Ok
					}
				}
				return ret, nil
			}
		}
	}
}
