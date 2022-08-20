package firewall

import (
	"fmt"
	"sync"
	"time"

	"github.com/emirpasic/gods/lists"
	"github.com/emirpasic/gods/lists/doublylinkedlist"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type RuleManager struct {
	fw Firewall

	rules lists.List
	lock  sync.Mutex

	stop chan struct{}
}

func NewRuleManager(fw Firewall) *RuleManager {
	r := &RuleManager{
		fw:    fw,
		rules: doublylinkedlist.New(),
	}
	return r
}

func (rm *RuleManager) Start() error {
	rm.stop = make(chan struct{})
	go rm.cleanupRoutine(rm.stop)
	return nil
}

func (rm *RuleManager) cleanupRoutine(stop chan struct{}) {
	t := time.NewTicker(time.Second)
	for {
		select {
		case <-t.C:
			if err := rm.cleanup(); err != nil {
				log.Error().Err(err).Msgf("Firewall Rule Manager failed to cleanup")
			}
		case <-stop:
			t.Stop()
			return
		}
	}
}

func (rm *RuleManager) cleanup() error {
	rm.lock.Lock()
	defer rm.lock.Unlock()

	last := 0
mainloop:
	for {
		size := rm.rules.Size()
		if size == 0 {
			break
		}
		for i, elm := range rm.rules.Values() {
			if i < last {
				continue
			}

			re, ok := elm.(RuleWithExpiration)
			if !ok {
				panic("invalid type in rule manger list")
			}

			if time.Now().After(re.Expiration()) {
				// remove
				err := rm.fw.RuleRemove(re.Rule)
				if err != nil {
					return errors.Wrap(err, "firewall rule remove")
				}

				rm.rules.Remove(i)
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

func (rm *RuleManager) removeAllRules() []error {
	rm.lock.Lock()
	defer rm.lock.Unlock()

	errs := make([]error, 0)

	for _, elm := range rm.rules.Values() {
		re, ok := elm.(RuleWithExpiration)
		if !ok {
			panic("invalid type in rule manger list")
		}

		err := rm.fw.RuleRemove(re.Rule)
		errs = append(errs, errors.Wrap(err, fmt.Sprintf("firewall rule: %s", re.String())))
	}

	rm.rules.Clear()

	return errs
}

func (rm *RuleManager) Stop() error {
	rm.stop <- struct{}{}
	errs := rm.removeAllRules()
	if len(errs) != 0 {
		for _, err := range errs {
			log.Error().Msgf(err.Error())
		}
	}
	return nil
}

func (rm *RuleManager) Add(r Rule, d time.Duration) error {
	re := RuleWithExpiration{
		Rule:     r,
		Duration: d,
		Created:  time.Now(),
	}

	rm.lock.Lock()
	rm.rules.Add(re)
	rm.lock.Unlock()

	err := rm.fw.RuleAdd(r)
	if err != nil {
		return errors.Wrap(err, "firewall rule add")
	}

	return nil
}

func (rm *RuleManager) Count() int {
	rm.lock.Lock()
	defer rm.lock.Unlock()
	return rm.rules.Size()
}

func (rm *RuleManager) Debug() map[string]interface{} {
	rm.lock.Lock()
	defer rm.lock.Unlock()

	rules := make([]string, 0, rm.rules.Size())
	for _, elm := range rm.rules.Values() {
		r, ok := elm.(Rule)
		if !ok {
			panic("invalid type in rules list")
		}

		rules = append(rules, r.String())
	}

	return map[string]interface{}{
		"rules": rules,
	}
}

type RuleWithExpiration struct {
	Rule     Rule
	Duration time.Duration
	Created  time.Time
}

func (re *RuleWithExpiration) String() string {
	return fmt.Sprintf("%s (expires in: %s)", re.Rule.String(), re.Duration.String())
}

func (re *RuleWithExpiration) Expiration() time.Time {
	return re.Created.Add(re.Duration)
}
