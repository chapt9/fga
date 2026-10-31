#!/bin/bash
# Smoke test of the R1-B roles, with R1-C labels, approvals and document
# publication, on one host
# (development profile): builds the binaries, creates a throwaway database,
# starts fga-decision, fga-keys and fga-storage on loopback, and drives them
# with fga and fga-admin.
#
#   scripts/smoke.sh WORKDIR
#
# Needs a local PostgreSQL reachable as localhost (createdb, dropdb, psql).
# Development keys and tokens only; nothing here is for production.
set -euo pipefail
check() { "$@" || { echo "SMOKE FAILED: $*"; exit 1; }; }
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
export FGA_BACKUP_KEY_PASSPHRASE="smoke backup passphrase"
$ADMIN backup-key generate -encrypt -out backup.key
grep -q '"format":"fga.keyfile/v1"' backup.key && echo "backup key is passphrase-protected"
$ADMIN bucket create -tenant t-acme -name reports -project p1 >/dev/null
for u in alice bob; do
  $ADMIN identity put -tenant t-acme -id $u -roles member -attrs '{"projects":["p1"]}'
  $ADMIN grant -tenant t-acme -actor $u -preset storage
  if [ $u = alice ]; then FGA_KEY_PASSPHRASE="alice passphrase" $B/fga keys init -dir $u -encrypt > $u.keys; else $B/fga keys init -dir $u > $u.keys; fi
  $ADMIN signing-key add -tenant t-acme -principal $u -public-key "$(awk '/^signer/{print $3}' $u.keys)" >/dev/null
done
tok() { $B/fga dev-token -key issuer.key -key-id tok-1 -sub $1 -tenant t-acme -aud $2 -ttl 30m; }
as() { export FGA_KEY_DIR=$1 FGA_TOKEN=$(tok $1 fga-storage) FGA_KEYS_TOKEN=$(tok $1 fga-keys) FGA_KEY_PASSPHRASE="$1 passphrase"
       export FGA_STORAGE_URL=http://127.0.0.1:18441 FGA_KEYS_URL=http://127.0.0.1:18442; }

as alice; $B/fga keys enroll -tenant t-acme -principal alice
as bob;   $B/fga keys enroll -tenant t-acme -principal bob
BOBFP=$(awk '/^recipient/{print $2}' bob.keys)
as alice; $B/fga trust add -recipient "$(awk '/^recipient/{print $3}' bob.keys)"
as bob;   $B/fga trust add -signer "$(awk '/^signer/{print $3}' alice.keys)"

head -c 3000000 /dev/urandom > plain.bin
grep -q '"format":"fga.keyfile/v1"' alice/recipient.key && grep -q '"format":"fga.keyfile/v1"' alice/signing.key && echo "alice's private keys are passphrase-protected"
as bob; check $B/fga keys protect; check grep -q fga.keyfile/v1 bob/signing.key; check $B/fga keys unprotect
if grep -q fga.keyfile/v1 bob/signing.key bob/recipient.key; then echo "SMOKE FAILED: unprotect left a protected file"; exit 1; fi
echo "bob's keys protected and unprotected"
as alice; if FGA_KEY_PASSPHRASE=wrong $B/fga ls -bucket reports 2>err.txt; then echo "UNEXPECTED: wrong passphrase accepted"; exit 1; else echo "wrong passphrase: $(cat err.txt)"; fi
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

# Labels and approvals (R1-C): raising is label, lowering is relabel, which
# the example policy allows only with an approval from a project lead.
$ADMIN identity put -tenant t-acme -id lena -roles member,lead -attrs '{"projects":["p1"]}'
$ADMIN grant -tenant t-acme -actor lena -preset storage
$ADMIN grant -tenant t-acme -actor lena -preset approver
$B/fga keys init -dir lena > lena.keys
as alice; check $B/fga label -bucket reports -key q3/report.bin -label confidential
as alice; if $B/fga label -bucket reports -key q3/report.bin -label internal 2>err.txt; then echo "UNEXPECTED: lowered without approval"; exit 1; fi
APPROVAL=$(sed -n 's/.*approval required: \([0-9a-f]*\);.*/\1/p' err.txt)
[ -n "$APPROVAL" ] || { echo "SMOKE FAILED: no approval ID: $(cat err.txt)"; exit 1; }
echo "lowering needs approval $APPROVAL"
as bob;   $B/fga approvals > approvals.txt; if grep -q "$APPROVAL" approvals.txt; then echo "UNEXPECTED: bob sees the approval"; exit 1; fi
as lena;  $B/fga approvals > approvals.txt; check grep -q "$APPROVAL" approvals.txt; cat approvals.txt
as lena;  check $B/fga approve $APPROVAL
as alice; check $B/fga label -bucket reports -key q3/report.bin -label internal -approval $APPROVAL
as alice; check $B/fga label -bucket reports -key q3/report.bin -label confidential
as alice; if $B/fga label -bucket reports -key q3/report.bin -label internal -approval $APPROVAL 2>err.txt; then echo "UNEXPECTED: approval used twice"; exit 1; fi
echo "approval used twice: $(cat err.txt)"
as bob;   check $B/fga propose-label -bucket reports -key q3/report.bin -label public -classifier smoke-classifier
as bob;   $B/fga get -bucket reports -key q3/report.bin -out bob.out && cmp plain.bin bob.out && echo "bob still reads after the label changes"

# Documents (R1-C): the client splits text into paragraph units, encrypts
# each with its own key and publishes them with a signed manifest at once.
printf 'First paragraph.\n\nSecond paragraph, with a line\nbreak.\n\nThird paragraph.\n' > notes.txt
as alice; check $B/fga put-document -bucket reports -key q3/notes.md -in notes.txt -to $BOBFP
UNITS=$(psql "$URL" -tAc "SELECT count(*) FROM document_units u JOIN document_versions d ON d.id = u.document_version WHERE d.state = 'LIVE'")
ENVS=$(psql "$URL" -tAc "SELECT count(*) FROM envelopes WHERE document_version IS NOT NULL")
[ "$UNITS" = 3 ] && [ "$ENVS" = 6 ] || { echo "SMOKE FAILED: $UNITS units, $ENVS unit envelopes"; exit 1; }
echo "document published: $UNITS units, $ENVS unit envelopes"
printf 'First paragraph.\n\nSecond paragraph, with a line\nbreak.\n\nThird paragraph.' > notes.expected
as alice; check $B/fga get-document -bucket reports -key q3/notes.md -out alice-notes.txt; check cmp notes.expected alice-notes.txt
as bob;   check $B/fga get-document -bucket reports -key q3/notes.md -out bob-notes.txt; check cmp notes.expected bob-notes.txt
echo "document read back by both recipients, unit by unit"
# The original file goes to its owner only: in the example policy members
# may read units but not raw-read a version (CNT-003).
as alice; check $B/fga put-document -bucket reports -key q3/report.md -in notes.txt -original plain.bin
as alice; check $B/fga get-original -bucket reports -key q3/report.md -out original.out; check cmp plain.bin original.out
as bob;   if $B/fga get-original -bucket reports -key q3/report.md -out x.out 2>err.txt; then echo "UNEXPECTED: bob read the original"; exit 1; fi
echo "original file: owner reads it; bob without raw-read: $(cat err.txt)"
as bob; if $B/fga get -bucket reports -key q3/notes.md -out x.out 2>err.txt; then echo "UNEXPECTED: a document read through the object API"; exit 1; fi
echo "object API on a document key: $(cat err.txt)"


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
