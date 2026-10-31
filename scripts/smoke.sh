#!/bin/bash
# Smoke test of the R1-B roles on one host (development profile): builds
# the binaries, creates a throwaway database, starts fga-decision, fga-keys
# and fga-storage on loopback, and drives them with fga and fga-admin.
#
#   scripts/smoke.sh WORKDIR
#
# Needs a local PostgreSQL reachable as localhost (createdb, dropdb, psql).
# Development keys and tokens only; nothing here is for production.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
rm -rf "$W/run" && mkdir -p "$W/run" && cd "$W/run"
DB=fga_smoke
dropdb -h localhost --if-exists $DB && createdb -h localhost $DB
URL="postgres://localhost:5432/$DB?sslmode=disable"
( cd $REPO && go build -o "$W/run/bin/" ./cmd/... )
B=$W/run/bin
$B/fga keys generate -out publisher >/dev/null
$B/fga keys generate -out decision >/dev/null
$B/fga keys generate -out issuer >/dev/null
$B/fga keys generate -out receipt >/dev/null
head -c 32 /dev/urandom | base64 > token.key
cp -R $REPO/examples/local/bundle bundle
$B/fga policy sign -key publisher.key -key-id publisher-1 -epoch 1 bundle
PUB=$(cat publisher.pub); DEC=$(cat decision.pub); ISS=$(cat issuer.pub)
cat > decision.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:17443","dev_adapter_id":"local-dev","database_url":"$URL",
 "bundle_dir":"bundle","publisher_keys":{"publisher-1":"$PUB"},"signing_key_file":"decision.key","signing_key_id":"decision-1",
 "audiences":["fga-storage","fga-keys"],"decision_max_age":"30s","outbox_capacity":100000,
 "token_issuer":{"issuer":"fga-dev","keys":{"tok-1":"$ISS"}},"adapter_audiences":{"local-dev":["fga-storage","fga-keys"]}}
J
COMMON="\"database_url\":\"$URL\",\"dev_adapter_id\":\"local-dev\",\"token_issuer\":{\"issuer\":\"fga-dev\",\"keys\":{\"tok-1\":\"$ISS\"}},\"decision\":{\"url\":\"http://127.0.0.1:17443\"},\"decision_keys\":{\"decision-1\":\"$DEC\"}"
cat > keys.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:18442",$COMMON,"journal_dir":"journal",
 "receipt_key_file":"receipt.key","receipt_key_id":"receipt-1","storage_adapter":"local-dev","outbox_capacity":100000}
J
cat > storage.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:18441",$COMMON,"blob_dir":"blobs",
 "keys":{"url":"http://127.0.0.1:18442"},"token_key_file":"token.key","outbox_capacity":100000}
J
$B/fga-decision -config decision.json > decision.log 2>&1 & echo $! > pids
sleep 2
$B/fga-keys -config keys.json > keys.log 2>&1 & echo $! >> pids
$B/fga-storage -config storage.json > storage.log 2>&1 & echo $! >> pids
trap 'kill $(cat pids) 2>/dev/null; sleep 1; dropdb -h localhost --if-exists '$DB'' EXIT
sleep 2
curl -sf http://127.0.0.1:18441/readyz && curl -sf http://127.0.0.1:18442/readyz && echo "roles ready"

ADMIN="$B/fga-admin -db $URL -journal journal -blobs blobs"
$ADMIN backup-key generate -out backup.key
$ADMIN bucket create -tenant t-acme -name reports -project p1 >/dev/null
for u in alice bob; do
  $ADMIN identity put -tenant t-acme -id $u -roles member -attrs '{"projects":["p1"]}'
  $ADMIN grant -tenant t-acme -actor $u -preset storage
  $B/fga keys init -dir $u > $u.keys
  $ADMIN signing-key add -tenant t-acme -principal $u -public-key "$(awk '/^signer/{print $3}' $u.keys)" >/dev/null
done
tok() { $B/fga dev-token -key issuer.key -key-id tok-1 -sub $1 -tenant t-acme -aud $2 -ttl 30m; }
as() { export FGA_KEY_DIR=$1 FGA_TOKEN=$(tok $1 fga-storage) FGA_KEYS_TOKEN=$(tok $1 fga-keys)
       export FGA_STORAGE_URL=http://127.0.0.1:18441 FGA_KEYS_URL=http://127.0.0.1:18442; }

as alice; $B/fga keys enroll -tenant t-acme -principal alice
as bob;   $B/fga keys enroll -tenant t-acme -principal bob
BOBFP=$(awk '/^recipient/{print $2}' bob.keys)
as alice; $B/fga trust add -recipient "$(awk '/^recipient/{print $3}' bob.keys)"
as bob;   $B/fga trust add -signer "$(awk '/^signer/{print $3}' alice.keys)"

head -c 3000000 /dev/urandom > plain.bin
as alice; $B/fga put -bucket reports -key q3/report.bin -in plain.bin -if-none-match
as alice; $B/fga get -bucket reports -key q3/report.bin -out alice.out && cmp plain.bin alice.out && echo "alice round trip OK"
as bob;   if $B/fga get -bucket reports -key q3/report.bin -out bob.out 2>err.txt; then echo "UNEXPECTED: bob read without an envelope"; exit 1; else echo "bob before sharing: $(cat err.txt)"; fi
as alice; $B/fga share -bucket reports -key q3/report.bin -to $BOBFP -key-version 1
as bob;   $B/fga get -bucket reports -key q3/report.bin -out bob.out && cmp plain.bin bob.out && echo "bob after sharing OK"
as bob;   $B/fga ls -bucket reports
python3 -I -c '
import glob,sys
p=open("plain.bin","rb").read()
blobs=[open(f,"rb").read() for f in glob.glob("blobs/blobs/*/*/*")]
assert len(blobs)==1 and all(p[i:i+32] not in blobs[0] for i in range(0,len(p),65536)), "plaintext found in a blob"
print("the blob holds no 32-byte plaintext sample")'


$ADMIN audit export -dir audit
$ADMIN backup -backup-key backup.key -out backup1
as alice; $B/fga rm -bucket reports -key q3/report.bin
as alice; if $B/fga get -bucket reports -key q3/report.bin -out x.out 2>/dev/null; then echo "UNEXPECTED: read after delete"; exit 1; fi; echo "deleted"
$ADMIN recipient revoke -tenant t-acme -fingerprint $BOBFP
$ADMIN audit export -dir audit
$ADMIN restore -backup-key backup.key -from backup1
as alice; if $B/fga get -bucket reports -key q3/report.bin -out x.out 2>err.txt; then echo "UNEXPECTED: read while admission closed"; exit 1; fi; echo "while closed: $(cat err.txt)"
$ADMIN reconcile
as alice; $B/fga get -bucket reports -key q3/report.bin -out alice2.out && cmp plain.bin alice2.out && echo "restored object readable by alice"
as bob;   if $B/fga get -bucket reports -key q3/report.bin -out x.out 2>err.txt; then echo "UNEXPECTED: revoked bob read"; exit 1; fi; echo "bob after restore (key revoked after backup): $(cat err.txt)"
psql -h localhost -d $DB -Atc "select kind, count(*) from audit_outbox group by kind order by kind"
$ADMIN audit export -dir audit
echo "audit events exported: $(cat audit/*.jsonl | wc -l | tr -d ' ') lines, $(cat audit/*.jsonl | python3 -I -c 'import sys,json;print(len({json.loads(l)["id"] for l in sys.stdin}))') unique"
echo SMOKE PASSED
