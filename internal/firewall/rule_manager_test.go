package firewall

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var ruleManagerExpirationTestingSleep = time.Second

func TestRuleManager_Expiration(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.Equal(t, 0, rm.Count())

	dur := time.Second
	r := Rule{
		Proto:   ProtoTCP,
		SrcIP:   net.IPv4(1, 2, 3, 4),
		DstIP:   net.IPv4(1, 1, 1, 1),
		DstPort: 80,
	}

	fw.On("RuleAdd", r).Return(nil).Once()
	fw.On("RuleRemove", r).Return(nil).Once()

	assert.NoError(t, rm.Add(r, dur))
	assert.Equal(t, 1, rm.Count())

	time.Sleep(ruleManagerExpirationTestingSleep + dur)
	assert.Equal(t, 0, rm.Count())

	assert.NoError(t, rm.Stop())
	fw.AssertExpectations(t)
}

func TestRuleManager_MultipleRules(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.Equal(t, 0, rm.Count())

	dur := time.Second
	dur2 := dur + ruleManagerExpirationTestingSleep + time.Second
	rulesCount := 10
	for i := 0; i < rulesCount; i++ {
		r := Rule{
			Proto:   ProtoTCP,
			SrcIP:   net.IPv4(1, 2, 3, 4),
			DstIP:   net.IPv4(1, 1, 1, 1),
			DstPort: 80 + i,
		}
		fw.On("RuleAdd", r).Return(nil).Once()
		fw.On("RuleRemove", r).Return(nil).Once()

		d := dur
		if i+1 == rulesCount {
			d = dur2
		}

		assert.NoError(t, rm.Add(r, d))
	}

	assert.Equal(t, rulesCount, rm.Count())

	time.Sleep(ruleManagerExpirationTestingSleep + dur)
	assert.Equal(t, 1, rm.Count())

	time.Sleep(ruleManagerExpirationTestingSleep + (dur2 - dur))
	assert.Equal(t, 0, rm.Count())

	assert.NoError(t, rm.Stop())
	fw.AssertExpectations(t)
}

func TestRuleManager_MultipleStartStop(t *testing.T) {
	fw := &FirewallMock{}
	rm := NewRuleManager(fw)

	assert.NoError(t, rm.Start())
	assert.NoError(t, rm.Stop())

	assert.NoError(t, rm.Start())
	assert.NoError(t, rm.Stop())

	assert.NoError(t, rm.Start())
	assert.NoError(t, rm.Stop())
}

func BenchmarkRuleManagerCleanupWithoutRemove_10Rules(b *testing.B) {
	ruleManagerCleanup(b, 10, time.Hour)
}

func BenchmarkRuleManagerCleanupWithoutRemove_100Rules(b *testing.B) {
	ruleManagerCleanup(b, 100, time.Hour)
}

func BenchmarkRuleManagerCleanupWithoutRemove_1000Rules(b *testing.B) {
	ruleManagerCleanup(b, 1000, time.Hour)
}

func BenchmarkRuleManagerCleanupWithoutRemove_10000Rules(b *testing.B) {
	ruleManagerCleanup(b, 10000, time.Hour)
}

func BenchmarkRuleManagerCleanupWithRemove_10Rules(b *testing.B) {
	ruleManagerCleanup(b, 10, time.Nanosecond)
}

func BenchmarkRuleManagerCleanupWithRemove_100Rules(b *testing.B) {
	ruleManagerCleanup(b, 100, time.Nanosecond)
}

func BenchmarkRuleManagerCleanupWithRemove_1000Rules(b *testing.B) {
	ruleManagerCleanup(b, 1000, time.Nanosecond)
}

func BenchmarkRuleManagerCleanupWithRemove_10000Rules(b *testing.B) {
	ruleManagerCleanup(b, 10000, time.Nanosecond)
}

func ruleManagerCleanup(b *testing.B, size int, dur time.Duration) {
	rm := NewRuleManager(&FirewallStub{})
	for i := 0; i < size; i++ {
		err := rm.Add(Rule{
			Proto:   ProtoUDP,
			SrcIP:   net.IPv4(1, 2, 3, 4),
			DstIP:   net.IPv4(1, 2, 3, 4),
			DstPort: 80 + i,
		}, dur)
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
