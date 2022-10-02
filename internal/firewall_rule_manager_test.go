package internal

import (
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/internal/observability"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var firewallRuleManagerExpirationTestingSleep = time.Second

func TestFirewallRuleManager_Expiration(t *testing.T) {
	SetMetricsRepository(observability.MetricsRepositoryStub{})

	fw := &FirewallMock{}
	rm := NewFirewallRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.Equal(t, 0, rm.Count())
	assert.Equal(t, 0, rm.metrics.rulesAdded.Get())
	assert.Equal(t, 0, rm.metrics.rulesRemoved.Get())

	dur := time.Second
	r := FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(1, 2, 3, 4),
		DstIP:        net.IPv4(1, 1, 1, 1),
		DstPortStart: 80,
	}

	fw.On("RuleAdd", r, mock.Anything).Return(nil).Once()
	fw.On("RuleRemove", r, mock.Anything).Return(nil).Once()

	assert.NoError(t, rm.Add(r, FirewallRuleMetadata{Duration: dur}))
	assert.Equal(t, 1, rm.Count())

	time.Sleep(firewallRuleManagerExpirationTestingSleep + dur)
	assert.Equal(t, 0, rm.Count())

	assert.NoError(t, rm.Stop())
	fw.AssertExpectations(t)

	assert.Equal(t, 1, rm.metrics.rulesAdded.Get())
	assert.Equal(t, 1, rm.metrics.rulesRemoved.Get())
}

func TestFirewallRuleManager_MultipleRules(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewFirewallRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.Equal(t, 0, rm.Count())

	dur := time.Second
	dur2 := dur + firewallRuleManagerExpirationTestingSleep + time.Second
	rulesCount := 10
	for i := 0; i < rulesCount; i++ {
		r := FirewallRule{
			Proto:        FirewallProtoTCP,
			SrcIP:        net.IPv4(1, 2, 3, 4),
			DstIP:        net.IPv4(1, 1, 1, 1),
			DstPortStart: 80 + i,
		}
		fw.On("RuleAdd", r, mock.Anything).Return(nil).Once()
		fw.On("RuleRemove", r, mock.Anything).Return(nil).Once()

		d := dur
		if i+1 == rulesCount {
			d = dur2
		}

		assert.NoError(t, rm.Add(r, FirewallRuleMetadata{Duration: d}))
	}

	assert.Equal(t, rulesCount, rm.Count())

	time.Sleep(firewallRuleManagerExpirationTestingSleep + dur)
	assert.Equal(t, 1, rm.Count())

	time.Sleep(firewallRuleManagerExpirationTestingSleep + (dur2 - dur))
	assert.Equal(t, 0, rm.Count())

	assert.NoError(t, rm.Stop())
	fw.AssertExpectations(t)
}

func TestFirewallRuleManager_MultipleStartStop(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewFirewallRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.NoError(t, rm.Stop())

	assert.NoError(t, rm.Start())
	assert.NoError(t, rm.Stop())

	assert.NoError(t, rm.Start())
	assert.NoError(t, rm.Stop())
}

func TestFirewallRuleManager_FirewallRuleNotAppliedShouldNotBeManaged(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewFirewallRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.Equal(t, 0, rm.Count())

	dur := time.Hour
	r := FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(1, 2, 3, 4),
		DstIP:        net.IPv4(1, 1, 1, 1),
		DstPortStart: 80,
	}

	fw.On("RuleAdd", r, mock.Anything).Return(errors.New("simulate error")).Once()

	assert.Error(t, rm.Add(r, FirewallRuleMetadata{Duration: dur}))
	assert.Equal(t, 0, rm.Count())

	assert.NoError(t, rm.Stop())
	fw.AssertExpectations(t)
}

func TestFirewallRuleManager_RemoveAllRules(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewFirewallRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.Equal(t, 0, rm.Count())

	dur := time.Hour
	r := FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(1, 2, 3, 4),
		DstIP:        net.IPv4(1, 1, 1, 1),
		DstPortStart: 80,
	}

	fw.On("RuleAdd", mock.Anything, mock.Anything).Return(nil).Times(5)
	fw.On("RuleRemove", mock.Anything, mock.Anything).Return(nil).Times(4)
	fw.On("RuleRemove", mock.Anything, mock.Anything).Return(errors.New("simulated error")).Times(1)

	for i := 0; i < 5; i++ {
		assert.NoError(t, rm.Add(r, FirewallRuleMetadata{Duration: dur}))
	}
	assert.Equal(t, 5, rm.Count())
	errs := rm.removeAllRules()
	assert.Len(t, errs, 1)

	assert.NoError(t, rm.Stop())
	fw.AssertExpectations(t)
}

func BenchmarkFirewallRuleManagerCleanupWithoutRemove_10Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 10, time.Hour)
}

func BenchmarkFirewallRuleManagerCleanupWithoutRemove_100Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 100, time.Hour)
}

func BenchmarkFirewallRuleManagerCleanupWithoutRemove_1000Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 1000, time.Hour)
}

func BenchmarkFirewallRuleManagerCleanupWithoutRemove_10000Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 10000, time.Hour)
}

func BenchmarkFirewallRuleManagerCleanupWithRemove_10Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 10, time.Nanosecond)
}

func BenchmarkFirewallRuleManagerCleanupWithRemove_100Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 100, time.Nanosecond)
}

func BenchmarkFirewallRuleManagerCleanupWithRemove_1000Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 1000, time.Nanosecond)
}

func BenchmarkFirewallRuleManagerCleanupWithRemove_10000Rules(b *testing.B) {
	firewallRuleManagerCleanup(b, 10000, time.Nanosecond)
}

func firewallRuleManagerCleanup(b *testing.B, size int, dur time.Duration) {
	rm := NewFirewallRuleManager(&FirewallStub{})
	for i := 0; i < size; i++ {
		err := rm.Add(FirewallRule{
			Proto:        FirewallProtoUDP,
			SrcIP:        net.IPv4(1, 2, 3, 4),
			DstIP:        net.IPv4(1, 2, 3, 4),
			DstPortStart: 80 + i,
		}, FirewallRuleMetadata{Duration: dur})
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := rm.cleanup(); err != nil {
			b.Fatal(err)
		}
	}
}
