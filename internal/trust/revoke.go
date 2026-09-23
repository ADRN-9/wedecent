package trust

import (
	"errors"
	"fmt"
	"strings"
)

var ErrPeerNotFound = errors.New("trusted peer not found")

// ValidPeerID accepts only canonical WeDecent device identities. Trust-file
// mutation commands use this before touching disk so malformed identifiers can
// never become broad or ambiguous deletion selectors.
func ValidPeerID(id string) bool {
	if len(id) != 19 || !strings.HasPrefix(id, "wd_") {
		return false
	}
	for _, r := range id[3:] {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}

// Revoke removes exactly one trusted peer from path and returns the record that
// was removed. DeletePeer reloads under the mutation lock first, so separate
// pairing and revocation processes cannot overwrite a newer snapshot.
func Revoke(path, id string) (Peer, error) {
	id = strings.TrimSpace(id)
	if !ValidPeerID(id) {
		return Peer{}, errors.New("invalid WeDecent device ID")
	}
	store, err := Open(path)
	if err != nil {
		return Peer{}, err
	}
	peer, deleted, err := store.DeletePeer(id)
	if err != nil {
		return Peer{}, err
	}
	if !deleted {
		return Peer{}, fmt.Errorf("%w: %s", ErrPeerNotFound, id)
	}
	return peer, nil
}
