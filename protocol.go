package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
)

type Member struct {
	i uint64
	skShare *big.Int
	pkShare Point
}

func main() {
	n := 9
	t := 5

	members, pk := RunKeygen(n, t)

	msg := []byte("message")

	// round 1
	participants := members[0:t]
	nonces := make([]Nonce, t)
	commits := make([]Commit, t)

	for j, memberJ := range participants {
		nonceJ, commitJ := round1(memberJ.i, memberJ.skShare)

		nonces[j] = nonceJ
		commits[j] = commitJ
	}

	// round 2
	shares := make([]*big.Int, t)

	for j, memberJ := range participants {
		shares[j] = round2(memberJ.i, memberJ.skShare, pk, nonces[j], msg, commits)

		if !verifySignatureShare(memberJ.i, memberJ.pkShare, commits[j], shares[j], commits, pk, msg) {
			fmt.Println("signature share failure")
		}
	}

	sig := aggregate(pk, commits, msg, shares)

	fmt.Println("--- verify signature ---")

	valid := BIP340Verify(ToBIP340(sig), ToBytes32(pk.X), msg)

	fmt.Println(valid)

	RunRoastCh(n, t, []int{
		GoodMember,
		DoesNotCommit,
		DoesNotRespond,
		RespondsMaliciously,
		RespondsMaliciously,
	})
}

func RunKeygen(n, t int) ([]Member, Point) {
	sk, pk := GenSharedKey()

	coeffs := GenPoly(sk, t)

	members := make([]Member, n)

	for j := range members {
		i := j + 1
		skShare := CalculatePoly(coeffs, i)
		pkShare := EcBaseMul(skShare)

		members[j] = Member{ uint64(i), skShare, pkShare }
	}

	return members, pk
}

func GenSharedKey() (*big.Int, Point) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	sk := OS2IP(b)
	sk.Mod(sk, G.q())

	pk := EcBaseMul(sk)

	if !HasEvenY(pk) {
		sk.Sub(G.q(), sk)
		pk = EcBaseMul(sk)
	}

	return sk, pk
}

func RunRoastCh(n, t int, corruption []int) {
	group, members := Initialise(n, t)
	CorruptMembers(members, corruption)

	memberChs := make([]MemberCh, n)
	for j, member := range members {
		fmt.Printf("preparing member channel %v\n", member.i)
		memberChs[j] = MemberCh {
			member.i,
			make(chan CommitRequest, 10),
			make(chan SignRequest, 10),
			make(chan bool, 1),
		}
	}
	coordinatorCh := CoordinatorCh {
		make(chan Commit, n*2),
		make(chan SignatureShare, n*2),
	}

	r1 := group.NewCoordinator([]byte("test"), 1)

	var wg sync.WaitGroup
	wg.Add(len(members) + 1)

	for j := range members {
		go func(member MemberState, ch MemberCh) {
			defer wg.Done()
			member.RunMember(coordinatorCh, ch)
		}(members[j], memberChs[j])
	}
	
	go func() {
		defer wg.Done()
		r1.RunCoordinator(coordinatorCh, memberChs)
	}()

	wg.Wait()
}

func RunRoast(n, t int) {
	group, members := Initialise(n, t)
	
	members[1].behaviour = DoesNotCommit

	r1 := group.NewCoordinator([]byte("test"), 1)

	commitRequest := r1.RequestCommits()

	commits := make([]Commit, 0)

	for _, member := range members {
		fmt.Printf("requesting commit from member %v\n", member.i)
		commit := member.RespondC(*commitRequest)
		if commit != nil {
			commits = append(commits, *commit)
		}
	}

	var signRequest *SignRequest
	for _, commit := range commits {
		fmt.Printf("processing commit from member %v\n", commit.i)
		sr := r1.ReceiveCommit(commit)
		if sr != nil {
			signRequest = sr
			break
		}
	}

	shares := make([]SignatureShare, 0)
	for _, commit := range signRequest.commits {
		member := members[commit.i - 1]
		fmt.Printf("requesting signature from member %v\n", commit.i)
		share := member.RespondS(*signRequest)
		if share != nil {
			shares = append(shares, *share)
			commits = append(commits, share.commit)
		}
	}

	for _, share := range shares {
		fmt.Printf("processing share %v\n", share.commit.i)
		sig := r1.ReceiveShare(share.commit.i, share.commitHash, share.share)
		if sig != nil {
			fmt.Println("successful signature\n")
		}
	}
}