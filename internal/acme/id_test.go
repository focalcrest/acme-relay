package acme

import "testing"

func TestIDGenerator_Next_Sequential(t *testing.T) {
	g := NewIDGenerator(0)
	if got := g.Next(); got != 1 {
		t.Errorf("first ID = %d, want 1", got)
	}
	if got := g.Next(); got != 2 {
		t.Errorf("second ID = %d, want 2", got)
	}
	if got := g.Next(); got != 3 {
		t.Errorf("third ID = %d, want 3", got)
	}
}

func TestIDGenerator_Next_WithSeed(t *testing.T) {
	g := NewIDGenerator(100)
	if got := g.Next(); got != 101 {
		t.Errorf("first ID = %d, want 101", got)
	}
	if got := g.Next(); got != 102 {
		t.Errorf("second ID = %d, want 102", got)
	}
}

func TestIDGenerator_Next_NegativeSeed(t *testing.T) {
	g := NewIDGenerator(-5)
	if got := g.Next(); got != 1 {
		t.Errorf("first ID with negative seed = %d, want 1", got)
	}
}
