package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

func (r *Router) newSniffOverrideRules(ctx context.Context, metadata *adapter.InboundContext) {
	in := metadata.Inbound
	if _, ok := r.sniffOverrideRules[in]; ok {
		return
	}
	rules := []adapter.SniffOverrideRule{}
	defer func() {
		r.sniffOverrideRules[in] = rules
	}()
	for i, sniffOverrideRuleOptions := range metadata.InboundOptions.SniffOverrideRules {
		sniffOverrideRule, err := NewSniffOverrideRule(r, r.logger, sniffOverrideRuleOptions)
		if err != nil {
			r.logger.Debug(E.Cause(err, "parse sniff_override rule[", i, "]"))
			return
		}
		sniffOverrideRule.UpdateGeosite()
		rules = append(rules, sniffOverrideRule)
	}
}

func (r *Router) matchSniffOverride(ctx context.Context, metadata *adapter.InboundContext) bool {
	r.newSniffOverrideRules(ctx, metadata)
	rules := r.sniffOverrideRules[metadata.Inbound]
	if len(rules) == 0 {
		r.overrideLogger.DebugContext(ctx, "match all")
		return true
	}
	for i, rule := range rules {
		if rule.Match(metadata) {
			r.overrideLogger.DebugContext(ctx, "match[", i, "] ", rule.String())
			return true
		}
	}
	return false
}
