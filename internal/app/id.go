package app

import (
	"crypto/rand"
	"errors"
	"math/big"
	"regexp"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func newID(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(idAlphabet)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = idAlphabet[idx.Int64()]
	}
	return string(b)
}

var (
	slugRE          = regexp.MustCompile(`^[A-Za-z0-9_-]{2,64}$`)
	reservedSlugSet = map[string]struct{}{
		"admin":       {},
		"api":         {},
		"raw":         {},
		"static":      {},
		"favicon.ico": {},
		"robots.txt":  {},
	}

	errSlugInvalid = errors.New(
		"invalid custom id (allowed: 2-64 chars, letters/digits/underscore/hyphen; reserved words disallowed)")
	errSlugTaken = errors.New("custom id already in use")
)

func validateSlug(s string) error {
	if !slugRE.MatchString(s) {
		return errSlugInvalid
	}
	if _, bad := reservedSlugSet[s]; bad {
		return errSlugInvalid
	}
	return nil
}
