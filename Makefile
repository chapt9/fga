.PHONY: check check-pg spec

# Local PostgreSQL used by check-pg; tests create and drop their own schema.
FGA_TEST_DATABASE_URL ?= postgres://localhost:5432/fga_test?sslmode=disable

check:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet ./...
	go test -race ./...

# check plus the PostgreSQL-backed tests, which otherwise skip.
check-pg: check
	FGA_TEST_DATABASE_URL='$(FGA_TEST_DATABASE_URL)' go test -race -count=1 ./internal/catalog/...

spec:
	python3 -I docs/spec/tools/check_spec.py
