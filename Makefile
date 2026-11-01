.PHONY: check check-pg spec smoke vuln ci

# Local PostgreSQL used by check-pg; tests create and drop their own schema.
FGA_TEST_DATABASE_URL ?= postgres://localhost:5432/fga_test?sslmode=disable

check:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go test -race ./...

# check, then every package again with the PostgreSQL-backed tests enabled
# (they skip without a database).
check-pg: check
	FGA_TEST_DATABASE_URL='$(FGA_TEST_DATABASE_URL)' go test -race -count=1 ./...

# Structural check of specification 2.6; --check-only leaves generated/ as is.
spec:
	python3 -I -B docs/spec/tools/check_spec.py --check-only
	python3 -I -B docs/spec/tools/test_check_spec.py

# The smoke run of every role on loopback (scripts/smoke.sh), in a
# work directory git ignores.
SMOKE_DIR ?= .local/smoke
smoke:
	scripts/smoke.sh $(SMOKE_DIR)

# Vulnerability scan (LIB-003, docs/dependencies/vulnerability-scan.md).
# It queries vuln.go.dev.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# Everything a release needs, run locally instead of a hosted CI: the
# checks with PostgreSQL (import allowlists included), the specification
# check, the smoke run and the vulnerability scan.
ci: check-pg spec smoke vuln
