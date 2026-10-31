package tools

import (
	"strings"
	"testing"

	"fga/internal/opplan"
	"fga/internal/registry"
)

func expenseTool() Tool {
	return Tool{
		ID: "expense.submit", Version: 3, Description: "Submit an expense to the finance system.",
		Destination: "expenses-local", Endpoint: Endpoint{Method: "POST", Path: "/expenses"},
		Arguments: []ArgSpec{
			{Name: "amount", Type: ArgMoney, Required: true},
			{Name: "vendor", Type: ArgString, Required: true, MaxLength: 64},
			{Name: "category", Type: ArgEnum, Values: []string{"travel", "meals"}},
			{Name: "source", Type: ArgResource, Required: true, Namespace: "mcp", ResourceType: "document.text_unit", Action: "read"},
		},
		Budget: "team-travel", AmountArgument: "amount", MaxHoldAge: "1h",
	}
}

const validArgs = `{"amount":{"currency":"EUR","minor":50000},"vendor":"Rail Co","category":"travel","source":"doc://q3#overview"}`

func TestValidate(t *testing.T) {
	types := registry.CoreTypes()
	if err := expenseTool().Validate(types); err != nil {
		t.Fatalf("valid tool rejected: %v", err)
	}
	for name, edit := range map[string]func(*Tool){
		"bad id":                    func(tl *Tool) { tl.ID = "Expense Submit" },
		"GET endpoint":              func(tl *Tool) { tl.Endpoint.Method = "GET" },
		"no hold age":               func(tl *Tool) { tl.MaxHoldAge = "" },
		"reserved argument name":    func(tl *Tool) { tl.Arguments[1].Name = "destination" },
		"empty enum":                func(tl *Tool) { tl.Arguments[2].Values = nil },
		"unregistered resource act": func(tl *Tool) { tl.Arguments[3].Action = "delete" },
		"budget without amount":     func(tl *Tool) { tl.AmountArgument = "" },
		"amount not money":          func(tl *Tool) { tl.AmountArgument = "vendor" },
	} {
		tl := expenseTool()
		edit(&tl)
		if err := tl.Validate(types); err == nil {
			t.Errorf("%s: Validate succeeded, want an error", name)
		}
	}
}

func TestParseArguments(t *testing.T) {
	tl := expenseTool()
	args, err := tl.ParseArguments([]byte(validArgs))
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := args.Money("amount"); m != (Money{Currency: "EUR", Minor: 50000}) {
		t.Errorf("amount = %+v", m)
	}

	for name, raw := range map[string]string{
		"unknown argument":      `{"amount":{"currency":"EUR","minor":1},"vendor":"x","source":"s","admin":true}`,
		"missing required":      `{"amount":{"currency":"EUR","minor":1},"source":"s"}`,
		"repeated argument":     `{"amount":{"currency":"EUR","minor":1},"vendor":"x","vendor":"y","source":"s"}`,
		"fractional money":      `{"amount":{"currency":"EUR","minor":1.5},"vendor":"x","source":"s"}`,
		"float money":           `{"amount":{"currency":"EUR","minor":1e3},"vendor":"x","source":"s"}`,
		"negative money":        `{"amount":{"currency":"EUR","minor":-1},"vendor":"x","source":"s"}`,
		"lowercase currency":    `{"amount":{"currency":"eur","minor":1},"vendor":"x","source":"s"}`,
		"string too long":       `{"amount":{"currency":"EUR","minor":1},"vendor":"` + strings.Repeat("x", 65) + `","source":"s"}`,
		"control character":     `{"amount":{"currency":"EUR","minor":1},"vendor":"x\u0000y","source":"s"}`,
		"enum value not listed": `{"amount":{"currency":"EUR","minor":1},"vendor":"x","category":"golf","source":"s"}`,
		"empty resource":        `{"amount":{"currency":"EUR","minor":1},"vendor":"x","source":""}`,
	} {
		if _, err := tl.ParseArguments([]byte(raw)); err == nil {
			t.Errorf("%s: ParseArguments succeeded, want an error", name)
		}
	}
}

// TestOperationDigest covers the basis of V-030 and V-034: changing the
// amount, or the tool's schema, is a different operation.
func TestOperationDigest(t *testing.T) {
	tl := expenseTool()
	a1, _ := tl.ParseArguments([]byte(validArgs))
	reordered, _ := tl.ParseArguments([]byte(`{"source":"doc://q3#overview","category":"travel","vendor":"Rail Co","amount":{"minor":50000,"currency":"EUR"}}`))
	if OperationDigest(tl, a1) != OperationDigest(tl, reordered) {
		t.Error("the same arguments in another order must give the same digest")
	}
	changed, _ := tl.ParseArguments([]byte(strings.Replace(validArgs, "50000", "500000", 1)))
	if OperationDigest(tl, a1) == OperationDigest(tl, changed) {
		t.Error("a changed amount must change the operation digest (V-030)")
	}
	edited := expenseTool()
	edited.Endpoint.Path = "/expenses/fast-track"
	if edited.SchemaDigest() == tl.SchemaDigest() || OperationDigest(edited, a1) == OperationDigest(tl, a1) {
		t.Error("a changed tool record must change its schema digest and the operation digest (V-034)")
	}
}

// TestSummaryComesFromThePlan covers APR-005 (V-033): the summary shows the
// canonical arguments, and the agent's text only as an unverified note.
func TestSummaryComesFromThePlan(t *testing.T) {
	tl := expenseTool()
	args, _ := tl.ParseArguments([]byte(validArgs))
	s := Summarize(tl, args, map[string]string{"source": "u-1"}, "Pay vendor X 50.00")
	if !strings.Contains(string(s.Details), `"minor":50000`) || s.UnverifiedNote != "Pay vendor X 50.00" || s.OperationDigest != OperationDigest(tl, args) ||
		len(s.Targets) != 2 || s.Targets[1] != (opplan.Target{Role: "source", ID: "u-1"}) {
		t.Fatalf("summary = %+v", s)
	}
}

func TestOperationChecks(t *testing.T) {
	op := expenseTool().Operation()
	var got []string
	for _, c := range op.Checks {
		got = append(got, c.Role+":"+c.Action)
	}
	if strings.Join(got, ",") != "tool:invoke,destination:send,source:read" {
		t.Fatalf("checks = %v", got)
	}
}
