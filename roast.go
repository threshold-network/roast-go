package main

import (
	"math/big"
)


type GroupData struct {
	Pubkey Point
	N int
	T int
	Ids []uint64
	PubkeyShares map[uint64]Point
}

type CommitRequest struct {
	coordinator uint64
	message []byte
}

type SignRequest struct {
	coordinator uint64
	message []byte
	commits []Commit
}

type SignatureShare struct {
	commitHash [32]byte
	share *big.Int
	commit Commit
}

func Initialise(n, t int) (*GroupData, []MemberState) {
	memberIds := make([]uint64, n)
	memberStates := make([]MemberState, n)

	sk, pk := GenSharedKey()

	group := GroupData{
		pk,
		n,
		t,
		memberIds,
		make(map[uint64]Point),
	}

	coeffs := GenPoly(sk, t)

	for j := range memberStates {
		i := j + 1
		group.Ids[j] = uint64(i)
		skShare := CalculatePoly(coeffs, i)
		pkShare := EcBaseMul(skShare)

		memberStates[j] = MemberState{
			uint64(i),
			GoodMember,
			pk,
			pkShare,
			skShare,
			make(map[[32]byte]*MemberResponse),
		}

		group.PubkeyShares[uint64(i)] = pkShare
	}

	return &group, memberStates
}

func (G *GroupData) NewCoordinator(message []byte, i uint64) *RoastExecution {
	return &RoastExecution{
		G,
		i,
		GoodCoordinator,
		message,
		make([]uint64, 0),
		make([]Commit, 0),
		make(map[[32]byte]RoastRequest),
	}
}

func CorruptMembers(members []MemberState, behaviours []int) {
	for i, b := range behaviours {
		members[i].behaviour = b
	}
}

func (R *RoastExecution) CorruptCoordinator(behaviour int) {
	R.behaviour = behaviour
}

func RoundId(coordinatorIndex uint64, roundNumber uint64) [32]byte {
	a := big.NewInt(int64(coordinatorIndex))
	b := big.NewInt(int64(roundNumber))
	abs := ToBytes32(a)
	bbs := ToBytes32(b)

	tag := []byte("roast/round_id")
	msg := concat(abs[:], bbs[:])

	return BIP340Hash(tag, msg)
}

func CommitHash(c Commit) [32]byte {
	tag := []byte("roast/commit_hash")
	ib := I2OSP(big.NewInt(int64(c.i)), 8) // FIXME: jank but will do for now
	return BIP340Hash(tag, concat(ib, c.hnc.Bytes(), c.bnc.Bytes()))
}

func CommitListHash(cs []Commit) [32]byte {
	bs := make([]byte, 0)

	for _, c := range cs {
		h := CommitHash(c)
		bs = concat(bs, h[:])
	}

	tag := []byte("roast/commit_list_hash")
	return BIP340Hash(tag, bs)
}