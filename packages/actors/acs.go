package actors

import (
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
	Actor[map[NodeID][]byte]
	f      int
	makeCC MakeCommonCoinFunc
}

// Constructor.
func NewACS(
	endpoint *Endpoint,
	f int,
	makeCC MakeCommonCoinFunc,
	log *slog.Logger,
) *ACS {
	return &ACS{
		Actor:  NewActor[map[NodeID][]byte](endpoint, log),
		f:      f,
		makeCC: makeCC,
	}
}

func (a *ACS) Run(vi []byte) {
	a.Go(func() {
		// > Let {RBC_i}_N refer to N instances of the reliable broadcast protocol,
		// > where P_i is the sender of RBC_i.
		rbcs := make([]*ReliableBroadcast, a.Endpoint().N())
		rbcDone := make(chan int)
		for i, nid := range a.Endpoint().Router.Peers {
			rbc := NewReliableBroadcast(a.Endpoint().Sub("rbc:%d", i), a.f, nid, a.Log())
			if nid == a.Endpoint().Me() {
				// >   • upon receiving input v_i, input v_i to RBC_i
				rbc.Broadcast(vi)
			} else {
				rbc.Receive()
			}
			a.Context().Wg.Go(func() {
				WaitOutputReady(a.Context(), rbc)
				rbcDone <- i
			})
			rbcs[i] = rbc
		}

		// > Let {BA_i}_N refer to N instances
		// > of the binary byzantine agreement protocol.
		abas := make([]*BinaryAgreement, a.Endpoint().N())
		abaDone := make(chan int)
		startABA := func(i int, input bool) {
			makeCC := func(endpoint *Endpoint, sid string) *CommonCoinBLSSig {
				return a.makeCC(endpoint, fmt.Sprintf("%s:%d", sid, i))
			}
			aba := NewBinaryAgreement(a.Endpoint().Sub("aba:%d", i), a.f, makeCC, a.Log())
			aba.Run(input)
			a.Context().Wg.Go(func() {
				WaitOutputReady(a.Context(), aba)
				abaDone <- i
			})
			abas[i] = aba
		}

		abaResults := make(map[int]bool)
		checkOutput := func() {
			if a.Output().IsReady() {
				return
			}

			// >   • once all instances of BA have completed, let C ⊂ [1..N] be the
			// >     indexes of each BA that delivered 1. Wait for the output v_j for
			// >     each RBC_j such that j ∈ C. Finally output ∪_{j∈C} v_j.
			if len(abaResults) >= a.Endpoint().N() {
				ret := make(map[NodeID][]byte)
				for i, val := range abaResults {
					if val {
						if !rbcs[i].Output().IsReady() {
							return
						}
						rbcOut := rbcs[i].Output().MustGet()
						ret[a.Endpoint().Router.Peers[i]] = rbcOut
					}
				}
				a.Log().Info("ACS done", "count", len(ret))
				a.SetOutput(ret)
			}
		}

		for {
			select {
			case <-a.Context().Done():
				panic(a.Context().Err())
			case j := <-rbcDone:
				// >   • upon delivery of v_j from RBC_j, if input has not yet been
				// >     provided to BA_j, then provide input 1 to BA_j.
				a.Log().Info("RBC done", "i", j, "output", rbcs[j].Output().MustGet())
				if abas[j] == nil {
					startABA(j, true)
				}
				checkOutput()
			case i := <-abaDone:
				// >   • upon delivery of value 1 from at least N − f instances of BA,
				// >     provide input 0 to each instance of BA that has not yet been
				// >     provided input.
				abaOut := abas[i].Output().MustGet()
				abaResults[i] = abaOut
				a.Log().Info("ABA done", "aba_done", len(abaResults), "output", abaOut)
				if lo.Count(lo.Values(abaResults), true) == a.Endpoint().N()-a.f {
					for i, aba := range abas {
						if aba == nil {
							startABA(i, false)
						}
					}
				}
				checkOutput()
			}
		}
	})
}
