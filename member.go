package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)


const (
	// this member will behave correctly at all times
	GoodMember = iota
	// this member will not send commitments to the coordinator
	DoesNotCommit = iota
	// this member will send commitments but will not send signature shares
	DoesNotRespond = iota
	// this member will send invalid signature shares
	RespondsMaliciously = iota
)

type MemberResponse struct {
	commit Commit
	nonce Nonce
	spent bool
}

type MemberState struct {
	i uint64
	behaviour int
	pk Point
	pki Point
	ski *big.Int
	// hash(coordinator index, commitHash) -> response to that coordinator
	responses map[[32]byte]*MemberResponse
}

// respond to a commit request
func (S *MemberState) RespondC(r CommitRequest) *Commit {
	//
	// Bad behaviour
	//
	b := S.behaviour
	if b == DoesNotCommit {
		return nil
	}
	//
	//
	//

	n, c := round1(S.i, S.ski)

	res := MemberResponse{ c, n, false }

	rh := ResponseHash(c, r.coordinator)

	S.responses[rh] = &res

	return &c
}

// respond to a signing request
func (S *MemberState) RespondS(r SignRequest) *SignatureShare {
	//
	// Bad behaviour
	//
	b := S.behaviour
	// return nothing
	if b == DoesNotRespond {
		return nil
	}
	//
	//
	//

	var found *MemberResponse
	found = nil

	requestId := CommitListHash(r.commits)

	for _, c := range r.commits {
		if c.i == S.i {
			rh := ResponseHash(c, r.coordinator)
			found = S.responses[rh]
		}
	}

	// we have not made a commit for this round
	// or we have already used the nonce for signing
	if found == nil || found.spent {
		return nil
	}

	// Make a new commit
	nn, cc := round1(S.i, S.ski)

	newres := MemberResponse{ cc, nn, false }

	rhh := ResponseHash(cc, r.coordinator)

	S.responses[rhh] = &newres

	//
	// Bad behaviour
	//
	// return an invalid value
	if b == RespondsMaliciously {
		bs := make([]byte, 32)
		_, err := rand.Read(bs)
		if err != nil {
			panic(err)
		}
		return &SignatureShare{requestId, HashToInt(bs), cc}
	}
	//
	//
	//

	n := found.nonce

	share := round2(S.i, S.ski, S.pk, n, r.message, r.commits)

	// Wipe the nonce to prevent reuse
	found.nonce = Nonce{nil, nil}
	found.spent = true

	return &SignatureShare{requestId, share, cc}
}

func (S *MemberState) RunMember(
	outCh CoordinatorCh,
	inCh MemberCh,
) {
	for {
		select {
		case cr := <- inCh.cr:
			fmt.Printf("member %v responding to commit request\n", S.i)
			commit := S.RespondC(cr)
			if commit != nil {
				outCh.com <- *commit
			}
		case sr := <- inCh.sr :
			fmt.Printf("member %v responding to sign request\n", S.i)
			share := S.RespondS(sr)
			if share != nil {
				s := *share
				outCh.shr <- s
			}
		case <-inCh.done:
			fmt.Printf("member %v done\n", S.i)
			return
		}
	}
}