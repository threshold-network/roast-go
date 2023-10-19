package main

import (
	// "math/big"
	"testing"
)

func NullPoint() Point {
	return Point{ nil, nil }
}

func MockCommit(i int) Commit {
	return Commit { uint64(i), NullPoint(), NullPoint() }
}

func MockCommits(is []int) []Commit {
	cs := make([]Commit, len(is))

	for j, i := range is {
		cs[j] = MockCommit(i)
	}

	return cs
}

func CommitsMatch(is []int, cs []Commit) bool {
	if len(is) != len(cs) {
		return false
	}
	for j, i := range is {
		if cs[j].i != uint64(i) {
			return false
		}
	}
	return true
}

func CheckMatch(t *testing.T, is []int, cs []Commit) {
	if !CommitsMatch(is, cs) {
		t.Fatalf("commits mismatch; expected %v, got %v", is, cs)
	}
}

func TestInsertCommit(t *testing.T) {
	i123 := []int{1, 2, 3}
	i124 := []int{1, 2, 4}
	i1234 := []int{1, 2, 3, 4}

	CheckMatch(
		t,
		i1234,
		InsertCommit(MockCommits(i123), MockCommit(4)),
	)

	CheckMatch(
		t,
		i1234,
		InsertCommit(MockCommits(i124), MockCommit(3)),
	)

	CheckMatch(
		t,
		i123,
		InsertCommit(MockCommits(i123), MockCommit(1)),
	)

	CheckMatch(
		t,
		[]int{1},
		InsertCommit([]Commit{}, MockCommit(1)),
	)
}