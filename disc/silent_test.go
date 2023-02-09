package discovery

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandFromHash(t *testing.T) {
	buff := make([]byte, 32)
	rand.Read(buff)
	r := RandFromHash{
		Hash: buff,
	}

	for i := 0; i < 1000; i++ {
		assert.Positive(t, r.Int63())
	}
}
