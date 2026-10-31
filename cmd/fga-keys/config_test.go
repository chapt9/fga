package main

import (
	"strings"
	"testing"

	"fga/internal/roleconfig"
)

// TestProductionRefusesDevelopmentKEKs covers SSE-002: a KEK ring file is
// development custody, which production refuses while D-13 is open.
func TestProductionRefusesDevelopmentKEKs(t *testing.T) {
	for _, profile := range []string{"production", "development"} {
		c := Config{Common: roleconfig.Common{Profile: profile}, KEKFile: "keks"}
		refused := strings.Contains(errorText(c.Validate()), "D-13")
		if refused != (profile == "production") {
			t.Errorf("profile %s: kek_file refused %t", profile, refused)
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
