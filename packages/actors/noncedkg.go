package actors

import (
	"fmt"
	"log/slog"
	"sort"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

// NonceDKG implements NonceDKG as described in <https://github.com/iotaledger/crypto-tss/>.
// > 4) Asynchronous nonce-DKG
// > Variant a)
// >
// >     Setup
// >         Run any DKG (preferably probably FROST-DKG) to derive the aggregated public key and private key share.
// >         This leads to a synchronous, non-robust setup phase.
// >     Nonce sharing (can be started any time before the signing process)
// >         For every party i:
// >             Sample secret s = a₀
// >             Run ACSSᵢ(s):
// >                 C=(A₀,A₁,…,Aₜ), e=(Enc_pk₀(y₀),…,Enc_pkₙ(yₙ)) ← VSSEncAndProve(s)
// >                 Broadcast (C,e) using Verified Reliable Broadcast (RBC) with predicate: C is valid
// >             On termination of ACSSⱼ:
// >                 sʲᵢ ← output
// >                 Tᵢ ← Tᵢ ∪ {j}
// >             Wait until |Tᵢ| ≥ n - f
// >     Signing process
// >         For every party i:
// >             Input Tᵢ (bit vector) into Verified ACS with predicate: |Tᵢ| ≥ n - f
// >             On termination of ACS:
// >                 𝒯 ← {j | the j-th bit is set in at least f+1 elements of the output}
// >                 (One can show that |𝒯| ≥ f + 1 will always hold. Thus, one honest dealer will always be included.)
// >                 Wait until 𝒯 ⊆ Tᵢ
// >                 (as for each j in 𝒯 at least one honest peer observed a termination of ACSSⱼ, this will eventually succeed.)
// >                 σᵢ ← sum(sʲᵢ for j in 𝒯)
// >             Create partial signature using the private key share and σᵢ as the nonce share
// >         Aggregate t partial signatures to form the valid signature
type NonceDKG struct {
	Actor
	IntermediateOutput *Output[[]int] // exactly f+1 indexes
	FinalOutput        *Output[*NonceDKGOutput]
	f                  int
	suite              suites.Suite
	peerPKs            map[NodeID]kyber.Point
	mySK               kyber.Scalar
	agreementResult    chan map[NodeID][]int
}

type NonceDKGOutput struct {
	Indexes   []int           // Indexes used to construct the final key.
	PubKey    kyber.Point     // The common/aggregated public key of the key set.
	PriShare  *share.PriShare // Final key share (can be nil until consensus is completed in the case of aggrExt==true).
	Commits   []kyber.Point   // Commitments for the final key shares.
	Threshold int
}

func NewNonceDKG(
	endpoint *Endpoint,
	f int,
	suite suites.Suite,
	peerPKs map[NodeID]kyber.Point,
	mySK kyber.Scalar,
	log *slog.Logger,
) *NonceDKG {
	return &NonceDKG{
		Actor:              NewActor(endpoint, log),
		IntermediateOutput: NewOutput[[]int](endpoint.Context()),
		FinalOutput:        NewOutput[*NonceDKGOutput](endpoint.Context()),
		f:                  f,
		suite:              suite,
		peerPKs:            peerPKs,
		mySK:               mySK,
		agreementResult:    make(chan map[NodeID][]int, 1),
	}
}

func (n *NonceDKG) AgreementResult(proposals map[NodeID][]int) {
	n.agreementResult <- proposals
}

func (n *NonceDKG) Start() {
	n.Go(func() {
		acssOutputs := map[int]*Output[*ACSSOutput]{}
		for i, nid := range n.Endpoint().Router.Peers {
			acss := NewACSS(
				n.Endpoint().Sub("acss:%d", i),
				n.f,
				n.suite,
				n.peerPKs,
				n.mySK,
				n.Log(),
			)
			acssOutputs[i] = acss.Output

			if nid == n.Endpoint().Me() {
				secret := n.suite.Scalar().Pick(n.suite.RandomStream())
				acss.MakeDealAndShare(secret)
			} else {
				acss.Receive(nid)
			}
		}
		acssDone := OutputsReadyChan(n.Context(), acssOutputs)

		// > Let Si = {}; Ti = {}
		st := map[int]*ACSSOutput{}

		// Output from the external consensus.
		var agreedT []int

		tryMakeFinalOutput := func() {
			if agreedT == nil || n.FinalOutput.IsReady() {
				return
			}
			var sumCommitPoly *share.PubPoly
			sum := n.suite.Scalar().Zero()
			for _, j := range agreedT {
				if _, ok := st[j]; !ok {
					// Don't have S/T[%v] yet, have to wait, agreedT=%+v, have S/T indexes: %v.", j, n.agreedT, lo.Keys(n.st))
					return
				}
				sum.Add(sum.Clone(), st[j].PriShare.V)
				//
				// Sum the polynomials as well.
				jCommitPoly := share.NewPubPoly(n.suite, nil, st[j].Commits)
				if sumCommitPoly == nil {
					sumCommitPoly = jCommitPoly
				} else {
					var err error
					sumCommitPoly, err = sumCommitPoly.Add(jCommitPoly)
					if err != nil {
						panic(fmt.Errorf("Unable to sum public commitments: %w", err))
					}
				}
			}
			_, sumCommit := sumCommitPoly.Info()
			n.FinalOutput.Set(&NonceDKGOutput{
				Indexes:   agreedT,
				PubKey:    sumCommit[0],
				PriShare:  &share.PriShare{I: n.Endpoint().MyIndex(), V: sum},
				Commits:   sumCommit,
				Threshold: n.Endpoint().N() - n.f,
			})
		}

		for {
			select {
			case <-n.Context().Done():
				return
			case <-n.Endpoint().Status():
				n.Log().Info("status", "intermediateOutput", n.IntermediateOutput.String(), "finalOutput", n.FinalOutput.String(), "st", len(st), "agreedT", len(agreedT))
			case j := <-acssDone:
				if _, ok := st[j]; ok {
					// Already set. Ignore the duplicate messages.
					continue
				}
				acssOutput := acssOutputs[j].MustGet()
				st[j] = acssOutput
				if len(st) == n.Endpoint().N()-n.f && !n.IntermediateOutput.IsReady() {
					t := make([]int, 0)
					for ti := range st {
						t = append(t, ti)
					}
					sort.Ints(t)
					n.IntermediateOutput.Set(t)
				}
				//
				// It is possible that the indexes are already decided and are waiting for the ACSS only.
				// Thus we have to try produce the final output.
				tryMakeFinalOutput()
			case proposals := <-n.agreementResult:
				if agreedT != nil {
					continue
				}
				if len(proposals) < n.Endpoint().N()-n.f {
					panic(fmt.Errorf("len(msg.proposals) < n.n - n.f, len=%v, n=%v, f=%v", len(proposals), n.Endpoint().N(), n.f))
				}
				voteCounts := make([]int, n.Endpoint().N())
				for _, proposal := range proposals {
					if len(proposal) < n.f+1 {
						n.Log().Warn("len(proposal) < f+1, that should not happen")
						continue
					}
					for i := range proposal {
						duplicatesFound := false
						for j := range proposal {
							if i != j && proposal[i] == proposal[j] {
								duplicatesFound = true
								n.Log().Warn("msgAgreementResult with duplicate votes")
							}
						}
						if !duplicatesFound {
							voteCounts[proposal[i]]++
						}
					}
				}
				agreedT = []int{}
				for i := range voteCounts {
					if voteCounts[i] >= n.f+1 {
						agreedT = append(agreedT, i)
					}
				}
				if len(agreedT) < n.f+1 {
					panic(fmt.Errorf("len(agreedT) < f+1, that should not happen, len=%v, f=%v", len(agreedT), n.f))
				}
				tryMakeFinalOutput()
			}
		}
	})
}
