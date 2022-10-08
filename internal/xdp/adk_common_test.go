package xdp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

func TestADKProofSynchronize_NumberOfSetProofCalls(t *testing.T) {
	const iterations = 4
	const iterationDur = time.Second

	m := &adkProofSetterMock{}
	s := newADKProofSynchronize(m, nil, iterationDur)

	m.On("setADKProof", mock.Anything).Return(nil).Times(iterations)

	s.Start()

	buffer := iterationDur / 10
	dur := (iterations - 1) * iterationDur // the first call to setADKProof should be done immediately (without waiting)
	time.Sleep(dur + buffer)

	s.Stop()

	m.AssertExpectations(t)
}

func TestADKProofSynchronize_StartStop(t *testing.T) {
	const iterations = 4
	const iterationDur = time.Second

	m := &adkProofSetterMock{}
	s := newADKProofSynchronize(m, nil, iterationDur)

	m.On("setADKProof", mock.Anything).Return(nil).Times(iterations)

	for i := 0; i < iterations; i++ {
		s.Start()
		buffer := iterationDur / 10
		time.Sleep(buffer)
		s.Stop()
	}

	m.AssertExpectations(t)
}

type adkProofSetterMock struct {
	mock.Mock
}

func (a *adkProofSetterMock) setADKProof(g ADKProofGenerator) error {
	args := a.Called(g)
	return args.Error(0)
}
