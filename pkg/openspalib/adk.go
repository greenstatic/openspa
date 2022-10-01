package openspalib

import (
	"crypto/rand"
	"encoding/base32"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
)

const (
	ADKSecretLen        = ADKLength // in bytes
	ADKSecretEncodedLen = 7
)

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func ADKGenerateSecret() (string, error) {
	secret := make([]byte, ADKSecretLen)
	n, err := rand.Read(secret)
	if err != nil {
		return "", errors.Wrap(err, "random number generation")
	}

	if n != ADKSecretLen {
		return "", errors.New("invalid random read length")
	}

	s := b32NoPadding.EncodeToString(secret)

	return s, nil
}

func ADKGenerateProof(secret string) (uint32, error) {
	passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period: 60,
		Skew:   1,
		Digits: 9,
	})

	if err != nil {
		return 0, errors.Wrap(err, "totp generate")
	}

	p, err := strconv.Atoi(passcode)
	if err != nil {
		return 0, errors.Wrap(err, "strconv")
	}

	return uint32(p), nil
}

// ADKProver is a cached version of the ADKGenerateProof function, which recalculates the proof when the cached
// version is older than a second. This avoids calculating the same proof for every single packet and instead calculating
// the proof at least every second opposed to multiple times per second (when receiving multiple packets with a second).
// Run the benchmarks to see the speedup numbers for your setup.
type ADKProver struct {
	secret string

	// last time the proof was calculated
	last  time.Time
	proof uint32
}

func NewADKProver(secret string) (ADKProver, error) {
	proof, err := ADKGenerateProof(secret)
	if err != nil {
		return ADKProver{}, errors.Wrap(err, "adk generate proof")
	}

	return ADKProver{
		last:   time.Now(),
		proof:  proof,
		secret: secret,
	}, nil
}

func (a *ADKProver) Proof() (uint32, error) {
	n := time.Now()
	if n.Sub(a.last).Seconds() > 1 {
		p, err := ADKGenerateProof(a.secret)
		if err != nil {
			return 0, err
		}
		a.proof = p
	}

	return a.proof, nil
}

var ErrADKProofMismatch = errors.New("adk proof mismatch")

// Valid compares the inputted proof with the actual proof, verifying that the inputted ADK proof is valid.
func (a *ADKProver) Valid(proof uint32) error {
	p, err := a.Proof()
	if err != nil {
		return errors.Wrap(err, "proof generation")
	}

	if p != proof {
		return ErrADKProofMismatch
	}

	return nil
}
