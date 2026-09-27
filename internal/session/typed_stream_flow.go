package session

import (
	"errors"
	"fmt"

	"wedecent.com/wedecent/internal/protocol"
)

var errTypedStreamCredit = errors.New("typed stream credit violation")

type typedStreamCredit struct {
	remaining uint32
}

func newTypedStreamCredit(initial uint32) (typedStreamCredit, error) {
	if initial == 0 || initial > protocol.MaxTypedStreamWindow {
		return typedStreamCredit{}, fmt.Errorf("%w: initial window", errTypedStreamCredit)
	}
	return typedStreamCredit{remaining: initial}, nil
}

func (c *typedStreamCredit) consume(bytes uint32) error {
	if bytes == 0 || bytes > c.remaining {
		return fmt.Errorf("%w: consume %d with %d remaining", errTypedStreamCredit, bytes, c.remaining)
	}
	c.remaining -= bytes
	return nil
}

func (c *typedStreamCredit) add(bytes uint32) error {
	if bytes == 0 || bytes > protocol.MaxTypedStreamWindow || c.remaining > protocol.MaxTypedStreamWindow-bytes {
		return fmt.Errorf("%w: add %d with %d remaining", errTypedStreamCredit, bytes, c.remaining)
	}
	c.remaining += bytes
	return nil
}

func (c typedStreamCredit) available() uint32 {
	return c.remaining
}
