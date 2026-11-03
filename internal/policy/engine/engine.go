// Package engine evaluates policy bundles in the fga.policy/v1 format and
// implements policy.Evaluator (specification 2.5, Section "Policy format").
//
// A matching deny always overrides an allow, across roles and scopes. The
// ceiling set only objects. Any condition error denies, and an evaluation
// stopped by its cost limit or by cancellation is reported as an error
// because the engine could not decide (POL-005, POL-009).
package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/interpreter"

	"fga/internal/policy"
	"fga/internal/policy/format"
)

// Environment identity of this evaluator build. A release manifest names
// the values it was validated against, and an instance prepares only a
// release that matches its own (REL-001, POL-010).
const (
	// EvaluatorVersion changes whenever evaluation semantics change. Version
	// 2 accepts request.now compared with a resource attribute's time
	// (POL-008, docs/design/policy-format-v1.md, time conditions).
	EvaluatorVersion = "fga.evaluator/2"
	// ExpressionLibrary is the CEL implementation and its pinned version.
	ExpressionLibrary = "cel.dev/cel-go v0.33.2"
	// Functions names the function allowlist: CEL's standard definitions
	// only, with no extension libraries and no I/O (POL-009).
	Functions = "cel-standard/v1"
)

// Options bound condition evaluation.
type Options struct {
	// CostLimit is the CEL cost limit for one condition evaluation.
	CostLimit uint64
}

// DefaultOptions holds the initial qualification limits of DEC-009.
var DefaultOptions = Options{CostLimit: 10_000}

// Engine is an immutable compiled bundle. It is safe for concurrent use.
type Engine struct {
	digest string
	rules  map[ruleKey][]rule
}

type ruleKey struct {
	set      policy.Set
	resource string
	scope    string
}

type rule struct {
	id       string
	deny     bool
	actions  map[string]bool
	roles    map[string]bool
	requires []string
	outputs  map[string]any
	program  cel.Program // nil when the rule has no condition
	// bounds are the instants at which the condition's comparisons of
	// request.now may change their outcome.
	bounds []timeBound
}

// Compile validates docs against schema and compiles every condition. The
// result serves only requests for the given bundle digest.
func Compile(digest string, docs []format.Document, schema format.Schema, opts Options) (*Engine, error) {
	if digest == "" {
		return nil, errors.New("engine: bundle digest is required")
	}
	if opts.CostLimit == 0 {
		return nil, errors.New("engine: a cost limit is required")
	}
	if err := format.ValidateBundle(docs, schema); err != nil {
		return nil, err
	}
	env, err := cel.NewEnv(
		cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("engine: condition environment: %w", err)
	}

	e := &Engine{digest: digest, rules: map[ruleKey][]rule{}}
	var errs []error
	for _, d := range docs {
		set := policy.SetBusiness
		if d.Set == format.SetCeiling {
			set = policy.SetCeiling
		}
		key := ruleKey{set: set, resource: d.Resource, scope: d.Scope}
		for _, r := range d.Rules {
			compiled := rule{
				id:       r.ID,
				deny:     r.Effect == format.EffectDeny,
				actions:  toSet(r.Actions),
				roles:    toSet(r.Roles),
				requires: r.Requires,
				outputs:  r.Outputs,
			}
			if r.When != "" {
				prg, bounds, err := compileCondition(env, r.When, opts)
				if err != nil {
					errs = append(errs, fmt.Errorf("rule %q: %w", r.ID, err))
					continue
				}
				compiled.program, compiled.bounds = prg, bounds
			}
			e.rules[key] = append(e.rules[key], compiled)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return e, nil
}

func compileCondition(env *cel.Env, expr string, opts Options) (cel.Program, []timeBound, error) {
	ast, issues := env.Compile(expr)
	if issues.Err() != nil {
		return nil, nil, issues.Err()
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, nil, fmt.Errorf("condition has type %s, want bool", ast.OutputType())
	}
	bounds, err := timeBounds(ast)
	if err != nil {
		return nil, nil, err
	}
	prg, err := env.Program(ast, cel.CostLimit(opts.CostLimit), cel.InterruptCheckFrequency(100))
	return prg, bounds, err
}

// ErrUnboundedTime rejects a use of request.now for which no sound
// next-change bound exists (POL-008, "Policy format", time conditions).
var ErrUnboundedTime = errors.New("request.now may only be compared directly with a timestamp literal or with a resource attribute's timestamp, " +
	"either give or take a duration literal")

// A timeBound is the instant at which one comparison of request.now may
// change its outcome (POL-008): a timestamp literal, or the time a resource
// attribute holds, plus offset.
type timeBound struct {
	at        time.Time
	attribute string
	offset    time.Duration
}

// instant is the bound for a request at now on a resource with attrs. An
// absent attribute bounds nothing: a comparison with it cannot be evaluated,
// so time does not change the outcome. An attribute that is present but not
// an RFC 3339 time, as CEL's timestamp() reads it, bounds the decision at
// now, so that it ends at once (fail closed).
func (b timeBound) instant(attrs map[string]any, now time.Time) (time.Time, bool) {
	if b.attribute == "" {
		return b.at, true
	}
	v, ok := attrs[b.attribute]
	if !ok {
		return time.Time{}, false
	}
	str, ok := v.(string)
	if !ok {
		return now, true
	}
	t, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return now, true
	}
	return t.Add(b.offset), true
}

var comparisons = map[string]bool{
	operators.Less: true, operators.LessEquals: true, operators.Greater: true,
	operators.GreaterEquals: true, operators.Equals: true, operators.NotEquals: true,
}

// timeBounds enforces the time rule: request.now appears only as one side
// of a direct comparison whose other side is an anchor, timestamp("<RFC 3339
// literal>") or timestamp(resource.attributes.<name>), optionally plus or
// minus duration("<literal>"). It returns each comparison's bound: for an
// attribute, the decision role reads the attribute from the resource the
// decision is bound to, so a change of it makes the decision stale anyway.
// The request variable itself may be used only through field selection, so
// request.now cannot be reached another way.
func timeBounds(ast *cel.Ast) ([]timeBound, error) {
	root := celast.NavigateAST(ast.NativeRep())
	var bounds []timeBound
	for _, ident := range celast.MatchDescendants(root, celast.KindMatcher(celast.IdentKind)) {
		if ident.AsIdent() != "request" {
			continue
		}
		sel, ok := ident.Parent()
		if !ok || sel.Kind() != celast.SelectKind || sel.AsSelect().IsTestOnly() {
			return nil, errors.New("request may be used only through its fields")
		}
		if sel.AsSelect().FieldName() != "now" {
			continue
		}
		cmp, ok := sel.Parent()
		if !ok || cmp.Kind() != celast.CallKind || !comparisons[cmp.AsCall().FunctionName()] || len(cmp.AsCall().Args()) != 2 {
			return nil, ErrUnboundedTime
		}
		other := cmp.AsCall().Args()[0]
		if other.ID() == sel.ID() {
			other = cmp.AsCall().Args()[1]
		}
		b, ok := anchor(other)
		if !ok {
			return nil, ErrUnboundedTime
		}
		bounds = append(bounds, b)
	}
	return bounds, nil
}

// anchor reads the side request.now is compared with: a timestamp literal
// or a resource attribute's timestamp, optionally plus or minus a duration
// literal.
func anchor(e celast.Expr) (timeBound, bool) {
	var offset time.Duration
	if e.Kind() == celast.CallKind && !e.AsCall().IsMemberFunction() && len(e.AsCall().Args()) == 2 {
		name := e.AsCall().FunctionName()
		if name != operators.Add && name != operators.Subtract {
			return timeBound{}, false
		}
		d, ok := durationLiteral(e.AsCall().Args()[1])
		if !ok {
			return timeBound{}, false
		}
		if offset = d; name == operators.Subtract {
			offset = -d
		}
		e = e.AsCall().Args()[0]
	}
	if t, ok := timestampLiteral(e); ok {
		return timeBound{at: t.Add(offset)}, true
	}
	if a, ok := timestampAttribute(e); ok {
		return timeBound{attribute: a, offset: offset}, true
	}
	return timeBound{}, false
}

// timestampLiteral reports the value of timestamp("...") with a constant
// RFC 3339 argument.
func timestampLiteral(e celast.Expr) (time.Time, bool) {
	arg, ok := timestampArgument(e)
	if !ok || arg.Kind() != celast.LiteralKind {
		return time.Time{}, false
	}
	str, ok := arg.AsLiteral().Value().(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, str)
	return t, err == nil
}

// timestampAttribute reports the name in timestamp(resource.attributes.<name>).
func timestampAttribute(e celast.Expr) (string, bool) {
	arg, ok := timestampArgument(e)
	if !ok || arg.Kind() != celast.SelectKind || arg.AsSelect().IsTestOnly() {
		return "", false
	}
	attrs := arg.AsSelect().Operand()
	if attrs.Kind() != celast.SelectKind || attrs.AsSelect().IsTestOnly() || attrs.AsSelect().FieldName() != "attributes" {
		return "", false
	}
	res := attrs.AsSelect().Operand()
	if res.Kind() != celast.IdentKind || res.AsIdent() != "resource" {
		return "", false
	}
	return arg.AsSelect().FieldName(), true
}

// timestampArgument is the single argument of a global timestamp() call.
func timestampArgument(e celast.Expr) (celast.Expr, bool) {
	if e.Kind() != celast.CallKind || e.AsCall().FunctionName() != "timestamp" || e.AsCall().IsMemberFunction() || len(e.AsCall().Args()) != 1 {
		return nil, false
	}
	return e.AsCall().Args()[0], true
}

// durationLiteral reports the value of duration("...") with a constant
// argument.
func durationLiteral(e celast.Expr) (time.Duration, bool) {
	if e.Kind() != celast.CallKind || e.AsCall().FunctionName() != "duration" || e.AsCall().IsMemberFunction() || len(e.AsCall().Args()) != 1 {
		return 0, false
	}
	arg := e.AsCall().Args()[0]
	if arg.Kind() != celast.LiteralKind {
		return 0, false
	}
	str, ok := arg.AsLiteral().Value().(string)
	if !ok {
		return 0, false
	}
	d, err := time.ParseDuration(str)
	return d, err == nil
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, it := range items {
		s[it] = true
	}
	return s
}

// Digest returns the digest of the bundle the engine was compiled from.
func (e *Engine) Digest() string { return e.digest }

// Evaluate implements policy.Evaluator.
func (e *Engine) Evaluate(ctx context.Context, req policy.Request) (policy.Result, error) {
	if req.SnapshotDigest != e.digest {
		return policy.Result{}, fmt.Errorf("engine: request names snapshot %q, engine holds %q", req.SnapshotDigest, e.digest)
	}
	if req.Set != policy.SetBusiness && req.Set != policy.SetCeiling {
		return policy.Result{}, fmt.Errorf("engine: unknown policy set %v", req.Set)
	}
	if err := ctx.Err(); err != nil {
		return policy.Result{}, err
	}
	vars := activation(req)
	out := policy.Result{Actions: make(map[string]policy.ActionResult, len(req.Actions))}
	for _, action := range req.Actions {
		res, err := e.evaluateAction(ctx, req, vars, action)
		if err != nil {
			return policy.Result{}, err
		}
		out.Actions[action] = res
	}
	return out, nil
}

// evaluateAction applies the rules of Section "Policy format" to one action.
func (e *Engine) evaluateAction(ctx context.Context, req policy.Request, vars map[string]any, action string) (policy.ActionResult, error) {
	var allowed, denied, errored bool
	var next time.Time
	requires := map[string]bool{}
	var outputs []map[string]any
	for _, scope := range format.ScopeChain(req.Resource.Scope) {
		for _, r := range e.rules[ruleKey{set: req.Set, resource: req.Resource.Kind, scope: scope}] {
			if !r.listsAction(action) {
				continue
			}
			// Every rule that lists the action bounds validity, whether or
			// not its roles or condition match (DEC-005).
			for _, b := range r.bounds {
				if t, ok := b.instant(req.Resource.Attributes, req.Now); ok && !t.Before(req.Now) && (next.IsZero() || t.Before(next)) {
					next = t
				}
			}
			if !r.applies(action, req.Principal.Roles) {
				continue
			}
			holds, err := r.holds(ctx, vars)
			if err != nil {
				var stopped interpreter.EvalCancelledError
				if errors.As(err, &stopped) {
					return policy.ActionResult{}, fmt.Errorf("engine: rule %q: %w", r.id, err)
				}
				errored = true
				continue
			}
			if holds && r.deny {
				denied = true
			} else if holds {
				allowed = true
				for _, p := range r.requires {
					requires[p] = true
				}
				if len(r.outputs) > 0 {
					outputs = append(outputs, r.outputs)
				}
			}
		}
	}
	var res policy.ActionResult
	switch {
	case errored:
		res = policy.ActionResult{Effect: policy.EffectDeny, Errored: true}
	case denied:
		res = policy.ActionResult{Effect: policy.EffectDeny}
	case req.Set == policy.SetCeiling:
		// No ceiling rule objects. This is not a grant.
		res = policy.ActionResult{Effect: policy.EffectAllow}
	case allowed:
		res = policy.ActionResult{Effect: policy.EffectAllow, Requires: sortedKeys(requires), Outputs: outputs}
	default:
		res = policy.ActionResult{Effect: policy.EffectDeny}
	}
	res.NextChange = next
	return res, nil
}

func (r rule) listsAction(action string) bool { return r.actions[action] || r.actions[format.Wildcard] }

func (r rule) applies(action string, roles []string) bool {
	if !r.listsAction(action) {
		return false
	}
	if r.roles[format.Wildcard] {
		return true
	}
	for _, role := range roles {
		if r.roles[role] {
			return true
		}
	}
	return false
}

func (r rule) holds(ctx context.Context, vars map[string]any) (bool, error) {
	if r.program == nil {
		return true, nil
	}
	val, _, err := r.program.ContextEval(ctx, vars)
	if err != nil {
		return false, err
	}
	b, ok := val.Value().(bool)
	if !ok {
		return false, fmt.Errorf("condition returned %v, want bool", val.Type())
	}
	return b, nil
}

// activation exposes the request to conditions. Attribute maps are never
// nil, so a missing attribute is a lookup error, not a null comparison.
func activation(req policy.Request) map[string]any {
	return map[string]any{
		"principal": map[string]any{
			"id":         req.Principal.ID,
			"roles":      orEmptyList(req.Principal.Roles),
			"attributes": orEmptyMap(req.Principal.Attributes),
		},
		"resource": map[string]any{
			"type":       req.Resource.Kind,
			"id":         req.Resource.ID,
			"scope":      req.Resource.Scope,
			"attributes": orEmptyMap(req.Resource.Attributes),
		},
		"request": map[string]any{"now": req.Now, "operation": orEmptyMap(req.Operation)},
	}
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func orEmptyList(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}
