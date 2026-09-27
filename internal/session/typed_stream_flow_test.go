package session

import (
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedStreamCreditConsumeAndReplenish(t *testing.T) {
	credit, err := newTypedStreamCredit(64 << 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := credit.consume(32 << 10); err != nil {
		t.Fatal(err)
	}
	if got := credit.available(); got != 32<<10 {
		t.Fatalf("available = %d", got)
	}
	if err := credit.add(16 << 10); err != nil {
		t.Fatal(err)
	}
	if got := credit.available(); got != 48<<10 {
		t.Fatalf("available after add = %d", got)
	}
}

func TestTypedStreamCreditRejectsUnderflowOverflowAndZero(t *testing.T) {
	if _, err := newTypedStreamCredit(0); !errors.Is(err, errTypedStreamCredit) {
		t.Fatalf("zero initial error = %v", err)
	}
	if _, err := newTypedStreamCredit(protocol.MaxTypedStreamWindow + 1); !errors.Is(err, errTypedStreamCredit) {
		t.Fatalf("oversized initial error = %v", err)
	}
	credit, err := newTypedStreamCredit(protocol.MaxTypedStreamWindow)
	if err != nil {
		t.Fatal(err)
	}
	if err := credit.add(1); !errors.Is(err, errTypedStreamCredit) {
		t.Fatalf("overflow add error = %v", err)
	}
	if err := credit.consume(0); !errors.Is(err, errTypedStreamCredit) {
		t.Fatalf("zero consume error = %v", err)
	}
	if err := credit.consume(protocol.MaxTypedStreamWindow); err != nil {
		t.Fatal(err)
	}
	if err := credit.consume(1); !errors.Is(err, errTypedStreamCredit) {
		t.Fatalf("underflow consume error = %v", err)
	}
	if err := credit.add(0); !errors.Is(err, errTypedStreamCredit) {
		t.Fatalf("zero add error = %v", err)
	}
}
