package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	// this coordinator will behave correctly at all times
	GoodCoordinator = iota
	// this coordinator will not announce its coordinator status and request commitments
	DoesNotRequestCommits = iota
	// this coordinator will not and request signature shares
	DoesNotRequestSignature = iota
	// this coordinator will not produce signatures from shares it has received
	DoesNotAggregate = iota
	// this coordinator will try to produce a signature for the wrong message
	ChangesMessage = iota
)

type RoastExecution struct {
	group *GroupData
	coordinatorIndex uint64
	behaviour int
	message []byte
	badMembers []uint64
	commits []Commit
	requests map[[32]byte]RoastRequest
}

type RoastRequest struct {
	identifier [32]byte
	Commitments []Commit
	Responses map[uint64]*big.Int
}

func (R *RoastExecution) RequestCommits() *CommitRequest {
	//
	// Bad behaviour
	//
	if R.behaviour == DoesNotRequestCommits {
		return nil
	}
	//
	//
	//

	return &CommitRequest{R.coordinatorIndex, R.message}
}

func (R *RoastExecution) HasBad(i uint64) bool {
	for _, bad := range R.badMembers {
		if i == bad {
			return true
		}
	}
	return false
}


// Coordinator behaviour:
// Receive a response from a member
func (R *RoastExecution) ReceiveCommit(commit Commit) *SignRequest {
	// filter out bad members' commits so we reject them in the future
	if R.HasBad(commit.i) {
		return nil
	}

	R.commits = InsertCommit(R.commits, commit)

	if len(R.commits) != R.group.T {
		return nil
	}

	requestMessage := R.message
	//
	// Bad behaviour
	//
	if R.behaviour == DoesNotRequestSignature {
		return nil
	}
	if R.behaviour == ChangesMessage {
		requestMessage = make([]byte, 32)
		_, err := rand.Read(requestMessage)
		if err != nil {
			panic(err)
		}
	}
	//
	//
	//


	cs := R.commits
	csHash := CommitListHash(cs)
	R.requests[csHash] = RoastRequest{
		csHash,
		cs,
		make(map[uint64]*big.Int),
	}
	R.commits = make([]Commit, 0)

	return &SignRequest{R.coordinatorIndex, requestMessage, cs}
}

func InsertCommit(ccs []Commit, c Commit) []Commit {
	cs := ccs
	commitCount := len(cs)
	// This is the first commit; just add it to the end.
	if commitCount == 0 {
		cs = append(cs, c)
		return cs
	}
	// This is not the first one, so iterate through the commitments.
	// cc is a commit outside the list,
	// whose correct insertion position we're trying to find.
	// Since the list is sorted in ascending order,
	// we skip commits until we find one whose identifier is higher than of cc,
	// and insert cc there, shifting all commits afterwards by one position.
	// This is good enough for the prototype,
	// but a large group version can use a better data structure.
	cc := c
	for j := 0; j < commitCount; j++ {
		ccc := cs[j]
		// This is a duplicate commit; do not add it again.
		if ccc.i == cc.i {
			return cs
		}
		// If we find a commit whose identifier is higher
		// than that of the commit we're inserting,
		// swap it with the inserted commit.
		// This keeps the commit list sorted in ascending order by ID.
		if ccc.i > cc.i {
			cs[j] = cc
			cc = ccc
		}
	}
	// We're done with the list,
	// so append the remaining commit to the end.
	cs = append(cs, cc)

	return cs
}

func (R *RoastExecution) ReceiveShare(memberId uint64, requestId [32]byte, share *big.Int) *BIP340Signature {
	req := R.requests[requestId]
	cs := req.Commitments
	res := req.Responses
	found := false
	var commit Commit
	for _, c := range(cs) {
		if c.i == memberId {
			found = true
			commit = c
		}
	}
	if !found {
		return nil
	}
	shareGood := verifySignatureShare(
		memberId,
		R.group.PubkeyShares[memberId],
		commit,
		share,
		cs,
		R.group.Pubkey,
		R.message,
	)
	if !shareGood {
		fmt.Printf("---- bad share; recording misbehaving member %v ----\n", memberId)
		R.badMembers = append(R.badMembers, memberId)
		return nil
	}
	res[memberId] = share
	
	if len(res) != R.group.T {
		return nil
	}
	// len(res) == T
	shares := make([]*big.Int, 0)

	for _, share := range res {
		shares = append(shares, share)
	}

	sig := aggregate(R.group.Pubkey, cs, R.message, shares)
	bipSig := ToBIP340(sig)

	// We return a good BIP-340 signature 50% of the time,
	// so we need to check if this one is valid.
	// If valid, we can finish.
	sigGood := BIP340Verify(bipSig, R.group.Pubkey.ToBytes32(), R.message)

	if sigGood {
		return &bipSig
	} else {
		return nil
	}
}

func SendSignRequests(
	outChs []MemberCh,
	sr SignRequest,
) {
	participants := participantsFromCommitList(sr.commits)
	fmt.Printf("requesting signatures from %v\n", participants)
	for _, p := range participants {
		for _, out := range outChs {
			if out.i == p {
				out.sr <- sr
			}
		}
	}
}

func (R *RoastExecution) RunCoordinator(
	inCh CoordinatorCh,
	outChs []MemberCh,
) BIP340Signature {
	fmt.Printf("coordinator %v requesting commits\n", R.coordinatorIndex)
	crptr := R.RequestCommits()
	cr := *crptr
	for _, out := range outChs {
		if !R.HasBad(out.i) {
			fmt.Printf("sending request to member %v\n", out.i)
			request := cr
			out.cr <- request
		}
	}

	for {
		select {
		case commit := <- inCh.com:
			RandomDelay(500)
			fmt.Printf("coordinator %v received commit from member %v\n", R.coordinatorIndex, commit.i)
			sr := R.ReceiveCommit(commit)
			if sr != nil {
				SendSignRequests(outChs, *sr)
			}
		case share := <- inCh.shr:
			RandomDelay(500)
			fmt.Printf("coordinator %v received share from member %v\n", R.coordinatorIndex, share.commit.i)
			sig := R.ReceiveShare(share.commit.i, share.commitHash, share.share)
			if sig != nil {
				fmt.Println("successful signature")
				for _, out := range outChs {
					out.done <- true
				}
				return *sig
			} else {
				sr := R.ReceiveCommit(share.commit)
				if sr != nil {
					SendSignRequests(outChs, *sr)
				}
			}
		}
	}
}