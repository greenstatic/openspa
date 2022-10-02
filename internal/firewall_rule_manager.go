package internal

import (
	"fmt"
	"sync"
	"time"

	"github.com/emirpasic/gods/lists"
	"github.com/emirpasic/gods/lists/doublylinkedlist"
	"github.com/greenstatic/openspa/internal/observability"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type FirewallRuleManager struct {
	fw Firewall

	rules lists.List
	lock  sync.Mutex

	stop    chan struct{}
	metrics firewallRuleManagerMetrics
}

type firewallRuleManagerMetrics struct {
	rulesAdded   observability.Counter
	rulesRemoved observability.Counter
}

func NewFirewallRuleManager(fw Firewall) *FirewallRuleManager {
	r := &FirewallRuleManager{
		fw:      fw,
		rules:   doublylinkedlist.New(),
		metrics: newFirewallRuleManagerMetrics(),
	}
	return r
}

func (frm *FirewallRuleManager) Start() error {
	frm.stop = make(chan struct{})
	go frm.cleanupRoutine(frm.stop)
	return nil
}

func (frm *FirewallRuleManager) cleanupRoutine(stop chan struct{}) {
	t := time.NewTicker(time.Second)
	for {
		select {
		case <-t.C:
			if err := frm.cleanup(); err != nil {
				log.Error().Err(err).Msgf("Firewall Rule Manager failed to cleanup")
			}
		case <-stop:
			t.Stop()
			return
		}
	}
}

func (frm *FirewallRuleManager) cleanup() error {
	frm.lock.Lock()
	defer frm.lock.Unlock()

	last := 0
mainloop:
	for {
		size := frm.rules.Size()
		if size == 0 {
			break
		}
		for i, elm := range frm.rules.Values() {
			if i < last {
				continue
			}

			re, ok := elm.(FirewallRuleWithExpiration)
			if !ok {
				panic("invalid type in rule manger list")
			}

			if time.Now().After(re.Expiration()) {
				// remove
				err := frm.fw.RuleRemove(re.Rule, re.Meta)
				if err != nil {
					return errors.Wrap(err, "firewall rule remove")
				}
				frm.metrics.rulesRemoved.Inc()

				frm.rules.Remove(i)
				last = i
				break
			}

			if i+1 == size {
				break mainloop
			}
		}
	}

	return nil
}

func (frm *FirewallRuleManager) removeAllRules() []error {
	frm.lock.Lock()
	defer frm.lock.Unlock()

	errs := make([]error, 0)

	for _, elm := range frm.rules.Values() {
		re, ok := elm.(FirewallRuleWithExpiration)
		if !ok {
			panic("invalid type in rule manger list")
		}

		err := frm.fw.RuleRemove(re.Rule, re.Meta)
		if err != nil {
			errs = append(errs, errors.Wrap(err, fmt.Sprintf("firewall rule: %s", re.String())))
		}
	}

	frm.rules.Clear()

	return errs
}

func (frm *FirewallRuleManager) Stop() error {
	frm.stop <- struct{}{}
	errs := frm.removeAllRules()
	if len(errs) != 0 {
		for _, err := range errs {
			log.Error().Msgf(err.Error())
		}
	}
	return nil
}

func (frm *FirewallRuleManager) Add(r FirewallRule, meta FirewallRuleMetadata) error {
	re := FirewallRuleWithExpiration{
		Rule:     r,
		Meta:     meta,
		Duration: meta.Duration,
		Created:  time.Now(),
	}

	err := frm.fw.RuleAdd(r, meta)
	if err != nil {
		return errors.Wrap(err, "firewall rule add")
	}

	frm.metrics.rulesAdded.Inc()

	frm.lock.Lock()
	frm.rules.Add(re)
	frm.lock.Unlock()

	return nil
}

func (frm *FirewallRuleManager) Count() int {
	frm.lock.Lock()
	defer frm.lock.Unlock()
	return frm.rules.Size()
}

func (frm *FirewallRuleManager) Debug() map[string]interface{} {
	frm.lock.Lock()
	defer frm.lock.Unlock()

	rules := make([]string, 0, frm.rules.Size())
	for _, elm := range frm.rules.Values() {
		r, ok := elm.(FirewallRule)
		if !ok {
			panic("invalid type in rules list")
		}

		rules = append(rules, r.String())
	}

	return map[string]interface{}{
		"rules": rules,
	}
}

func newFirewallRuleManagerMetrics() firewallRuleManagerMetrics {
	f := firewallRuleManagerMetrics{}
	mr := getMetricsRepository()
	lbl := observability.NewLabels()

	f.rulesAdded = mr.Count("fw_rules_added", lbl)
	f.rulesRemoved = mr.Count("fw_rules_removed", lbl)

	return f
}

type FirewallRuleWithExpiration struct {
	Rule     FirewallRule
	Meta     FirewallRuleMetadata
	Duration time.Duration
	Created  time.Time
}

func (re *FirewallRuleWithExpiration) String() string {
	return fmt.Sprintf("%s (expires in: %s)", re.Rule.String(), re.Duration.String())
}

func (re *FirewallRuleWithExpiration) Expiration() time.Time {
	return re.Created.Add(re.Duration)
}
