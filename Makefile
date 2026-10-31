.PHONY: check check-pg spec

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

# Structural check of specification 2.5; --check-only leaves generated/ as is.
spec:
	python3 -I docs/spec/tools/check_spec.py --check-only
	python3 -I docs/spec/tools/test_check_spec.py
