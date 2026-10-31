package admission

import "testing"

func TestLimits(t *testing.T) {
	l := New(Limits{TenantRequests: 3, TenantStreams: 1, TotalRequests: 4})
	r1, ok := l.Acquire("a", true)
	if !ok {
		t.Fatal("first stream refused")
	}
	if _, ok := l.Acquire("a", true); ok {
		t.Fatal("a second stream of the tenant was admitted")
	}
	r2, _ := l.Acquire("a", false)
	r3, _ := l.Acquire("a", false)
	if _, ok := l.Acquire("a", false); ok {
		t.Fatal("a fourth request of the tenant was admitted")
	}
	r4, ok := l.Acquire("b", true)
	if !ok {
		t.Fatal("another tenant was refused while under its own limits")
	}
	if _, ok := l.Acquire("c", false); ok {
		t.Fatal("the total bound was exceeded")
	}
	r1()
	r1() // releasing twice counts once
	if _, ok := l.Acquire("a", true); !ok {
		t.Fatal("a released stream slot was not reusable")
	}
	r2()
	r3()
	r4()
	if (Limits{}).Validate() == nil || DefaultLimits.Validate() != nil {
		t.Error("validation")
	}
}
