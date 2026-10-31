#!/bin/bash
# Smoke test of the R1-B roles, with R1-C labels, approvals and document
# publication, the 2.6 encryption modes and the R2 MCP role, on one host
# (development profile): builds the binaries, creates a throwaway database,
# starts fga-decision, fga-keys, fga-storage and fga-mcp on loopback, and
# drives them with fga, fga-admin and a minimal MCP client.
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
 "audiences":["fga-storage","fga-keys","fga-tools"],"decision_max_age":"30s","outbox_capacity":100000,
 "token_issuer":{"issuer":"fga-dev","keys":{"tok-1":"$ISS"}},"adapter_audiences":{"local-dev":["fga-storage","fga-keys","fga-mcp","fga-tools"]},
 "gateways":{"local-dev":["fga-storage","fga-tools"]}}
J
COMMON="\"database_url\":\"$URL\",\"dev_adapter_id\":\"local-dev\",\"token_issuer\":{\"issuer\":\"fga-dev\",\"keys\":{\"tok-1\":\"$ISS\"}},\"decision\":{\"url\":\"http://127.0.0.1:17443\"},\"decision_keys\":{\"decision-1\":\"$DEC\"}"
cat > keys.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:18442",$COMMON,"journal_dir":"journal",
 "receipt_key_file":"receipt.key","receipt_key_id":"receipt-1","storage_adapter":"local-dev","outbox_capacity":100000,
 "kek_file":"keks"}
J
cat > storage.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:18441",$COMMON,"blob_dir":"blobs","journal_dir":"journal",
 "keys":{"url":"http://127.0.0.1:18442"},"token_key_file":"token.key","outbox_capacity":100000,"mcp_adapters":["local-dev"]}
J
cat > mcp.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:18446","token_issuer":{"issuer":"fga-dev","keys":{"tok-1":"$ISS"}},
 "audience":"fga-mcp","storage_audience":"fga-storage","decision":{"url":"http://127.0.0.1:17443"},
 "storage":{"url":"http://127.0.0.1:18441"},"buckets":["shared"],"tools":{"url":"http://127.0.0.1:18448"},"tools_audience":"fga-tools",
 "public_url":"http://127.0.0.1:18446/mcp","authorization_servers":["http://127.0.0.1:18446/dev-issuer"],"allowed_origins":["http://127.0.0.1:18446"]}
J
$B/fga-decision -config decision.json > decision.log 2>&1 & echo $! > pids
sleep 2
# The security journal is created once, before the keys role opens it; a
# missing journal is never recreated implicitly.
$B/fga-admin -db $URL -journal journal journal init > /dev/null
# Server-mode key-encryption keys (D-12, S2): a passphrase-protected
# development ring with the tenant's first KEK version, which the keys role
# opens at start. Server-mode uploads come with S3.
export FGA_KEK_PASSPHRASE="smoke kek passphrase"
$B/fga-admin -db $URL kek init -file keks -encrypt
$B/fga-admin -db $URL kek rotate -tenant t-acme -file keks
grep -q '"format":"fga.keyfile/v1"' keks && echo "KEK ring is passphrase-protected"
$B/fga-keys -config keys.json > keys.log 2>&1 & echo $! >> pids
$B/fga-storage -config storage.json > storage.log 2>&1 & echo $! >> pids
$B/fga-mcp -config mcp.json > mcp.log 2>&1 & echo $! >> pids
trap 'kill $(cat pids) 2>/dev/null; sleep 1; dropdb -h localhost --if-exists '$DB'' EXIT
sleep 2
curl -sf http://127.0.0.1:18441/readyz && curl -sf http://127.0.0.1:18442/readyz && curl -sf http://127.0.0.1:18446/healthz && echo "roles ready"

ADMIN="$B/fga-admin -db $URL -journal journal -blobs blobs"
export FGA_BACKUP_KEY_PASSPHRASE="smoke backup passphrase"
$ADMIN backup-key generate -encrypt -out backup.key
grep -q '"format":"fga.keyfile/v1"' backup.key && echo "backup key is passphrase-protected"
$ADMIN bucket create -tenant t-acme -name reports -project p1 -encryption client >/dev/null
for u in alice bob; do
  $ADMIN identity put -tenant t-acme -id $u -roles member -attrs '{"projects":["p1"]}'
  $ADMIN grant -tenant t-acme -actor $u -preset storage
  if [ $u = alice ]; then FGA_KEY_PASSPHRASE="alice passphrase" $B/fga keys init -dir $u -encrypt > $u.keys; else $B/fga keys init -dir $u > $u.keys; fi
  # alice's content-signing key is provisioned by the administrator; bob
  # enrolls his own below, with a possession proof (RCP-002).
  if [ $u = alice ]; then $ADMIN signing-key add -tenant t-acme -principal $u -public-key "$(awk '/^signer/{print $3}' $u.keys)" >/dev/null; fi
done
tok() { $B/fga dev-token -key issuer.key -key-id tok-1 -sub $1 -tenant t-acme -aud $2 -ttl 30m; }
as() { export FGA_KEY_DIR=$1 FGA_TOKEN=$(tok $1 fga-storage) FGA_KEYS_TOKEN=$(tok $1 fga-keys) FGA_KEY_PASSPHRASE="$1 passphrase"
       export FGA_STORAGE_URL=http://127.0.0.1:18441 FGA_KEYS_URL=http://127.0.0.1:18442; }

as alice; $B/fga keys enroll -tenant t-acme -principal alice
as bob;   $B/fga keys enroll -tenant t-acme -principal bob
as bob;   check $B/fga keys enroll-signer -tenant t-acme -principal bob
BOBFP=$(awk '/^recipient/{print $2}' bob.keys)
as alice; $B/fga trust add -recipient "$(awk '/^recipient/{print $3}' bob.keys)"
as bob;   $B/fga trust add -signer "$(awk '/^signer/{print $3}' alice.keys)"

head -c 3000000 /dev/urandom > plain.bin
grep -q '"format":"fga.keyfile/v1"' alice/recipient.key && grep -q '"format":"fga.keyfile/v1"' alice/signing.key && echo "alice's private keys are passphrase-protected"
as bob; check $B/fga keys protect; check grep -q fga.keyfile/v1 bob/signing.key; check $B/fga keys unprotect
if grep -q fga.keyfile/v1 bob/signing.key bob/recipient.key; then echo "SMOKE FAILED: unprotect left a protected file"; exit 1; fi
echo "bob's keys protected and unprotected"
as alice; if FGA_KEY_PASSPHRASE=wrong $B/fga ls -bucket reports 2>err.txt; then echo "UNEXPECTED: wrong passphrase accepted"; exit 1; else echo "wrong passphrase: $(cat err.txt)"; fi
as alice; PUT_OUT=$($B/fga put -bucket reports -key q3/report.bin -in plain.bin -if-none-match); echo "$PUT_OUT"
as alice; $B/fga get -bucket reports -key q3/report.bin -out alice.out && cmp plain.bin alice.out && echo "alice round trip OK"
as bob;   if $B/fga get -bucket reports -key q3/report.bin -out bob.out 2>err.txt; then echo "UNEXPECTED: bob read without an envelope"; exit 1; else echo "bob before sharing: $(cat err.txt)"; fi
as alice; $B/fga share -bucket reports -key q3/report.bin -to $BOBFP -key-version 1
as bob;   $B/fga get -bucket reports -key q3/report.bin -out bob.out && cmp plain.bin bob.out && echo "bob after sharing OK"
as bob;   $B/fga ls -bucket reports

# Derived outputs (R1-C): a summary derived from the report carries signed
# lineage; it is delivered only to readers of every source or by
# declassification.
SRC=$(echo "$PUT_OUT" | awk '{print "storage.object:" $4 ":" $6}')
echo "summary of the quarterly report" > summary.txt
as alice; check $B/fga put -bucket reports -key q3/summary.txt -in summary.txt -sources $SRC
as alice; check $B/fga get-derived -bucket reports -key q3/summary.txt -out summary.out; check cmp summary.txt summary.out
as bob;   if $B/fga get-derived -bucket reports -key q3/summary.txt -out x.out 2>err.txt; then echo "UNEXPECTED: bob read a derived output without an envelope"; exit 1; fi
echo "derived output: owner reads it; bob without an envelope: $(cat err.txt)"
python3 -I -c '
import glob,sys
p=open("plain.bin","rb").read()
blobs=[open(f,"rb").read() for f in glob.glob("blobs/blobs/*/*/*")]
assert len(blobs)>=1 and all(p[i:i+32] not in b for b in blobs for i in range(0,len(p),65536)), "plaintext found in a blob"
print("no blob holds a 32-byte plaintext sample")'

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
# A label proposal counts only from a registered classifier, signed by its
# key (LAB-002); bob's client is registered as one, and stays advisory.
if $B/fga propose-label -bucket reports -key q3/report.bin -label public -classifier smoke-classifier 2>err.txt; then
  echo "UNEXPECTED: an unregistered classifier's proposal was recorded"; exit 1; fi
$ADMIN classifier add -tenant t-acme -id smoke-classifier -signer "$(awk '/^signer/{print $2}' bob.keys)"
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
as bob;   $B/fga search -bucket reports -prefix q3/ > search.txt; check grep -q 'q3/notes.md' search.txt; check grep -q 'q3/report.md' search.txt
echo "metadata search finds $(wc -l < search.txt | tr -d ' ') documents for bob"
as bob; if $B/fga get -bucket reports -key q3/notes.md -out x.out 2>err.txt; then echo "UNEXPECTED: a document read through the object API"; exit 1; fi
echo "object API on a document key: $(cat err.txt)"
# Text collections (DOC-005): one text entry per paragraph. An append is a
# new version that keeps every entry, re-sealed with keys from the
# appender's own envelopes; bob may read the entries but not append.
printf 'hello\n\nhow are you?\n' > chat1.txt
printf 'fine, thanks\n' > chat2.txt
as alice; check $B/fga put-document -bucket reports -key q3/chat.log -in chat1.txt -to $BOBFP -collection
as alice; check $B/fga append -bucket reports -key q3/chat.log -in chat2.txt -to $BOBFP
printf 'hello\n\nhow are you?\n\nfine, thanks' > chat.expected
as bob;   check $B/fga get-document -bucket reports -key q3/chat.log -out bob-chat.txt; check cmp chat.expected bob-chat.txt
as bob;   if $B/fga append -bucket reports -key q3/chat.log -in chat2.txt 2>err.txt; then echo "UNEXPECTED: bob appended"; exit 1; fi
echo "collection appended by its owner and read back by bob; bob's append: $(cat err.txt)"

# Encryption modes (specification 2.6, D-12): a new bucket is in server
# mode by default, and takes no recipients. A project lead may change the
# mode, for uploads begun afterwards; earlier versions keep theirs, and
# fga get reads each version through its own mode's route.
$ADMIN bucket create -tenant t-acme -name vault -project p1 >/dev/null
$ADMIN grant -tenant t-acme -actor lena -type storage.bucket -actions manage
as alice; check $B/fga put -bucket vault -key a.bin -in plain.bin
as alice; if $B/fga put -bucket vault -key b.bin -in plain.bin -to $BOBFP 2>err.txt; then echo "UNEXPECTED: recipients in server mode"; exit 1; fi
echo "recipients for a server-mode bucket: $(cat err.txt)"
as bob;   if $B/fga set-encryption -bucket vault -encryption client 2>err.txt; then echo "UNEXPECTED: bob changed the mode"; exit 1; fi
echo "bob changes the mode: $(cat err.txt)"
as lena;  check $B/fga set-encryption -bucket vault -encryption client
as alice; check $B/fga put -bucket vault -key b.bin -in plain.bin
as alice; check $B/fga get -bucket vault -key a.bin -out vault-a.out; check cmp plain.bin vault-a.out
as alice; check $B/fga get -bucket vault -key b.bin -out vault-b.out; check cmp plain.bin vault-b.out
echo "after the lead switched the bucket to client mode, both versions read through their own modes"

# Server-mode objects (D-12, S3): in a bucket left in the default server
# mode, the storage role encrypts under a data key the keys role seals for
# the upload, and bob reads alice's object by policy alone: no recipient
# key, envelope or sharing step. No blob holds plaintext.
$ADMIN bucket create -tenant t-acme -name shared -project p1 >/dev/null
head -c 2500000 /dev/urandom > shared.bin
as alice; SHARED_OUT=$($B/fga put -bucket shared -key q4/plan.bin -in shared.bin) || { echo "SMOKE FAILED: server-mode put"; exit 1; }; echo "$SHARED_OUT"
as bob;   check $B/fga get -bucket shared -key q4/plan.bin -out bob-shared.out; check cmp shared.bin bob-shared.out
echo "server mode: bob reads alice's object by policy alone"
python3 -I -c '
import glob
p=open("shared.bin","rb").read()
blobs=[open(f,"rb").read() for f in glob.glob("blobs/blobs/*/*/*")]
assert blobs and all(p[i:i+32] not in b for b in blobs for i in range(0,len(p),65536)), "server-mode plaintext found in a blob"
print("no blob holds a sample of the server-mode plaintext")'
# Server-mode documents and collections (D-12, S4a): the storage role
# splits the text into units, each under its own data key; bob reads them
# by policy alone, and the owner appends to a collection with no client
# keys.
as alice; check $B/fga put-document -bucket shared -key q4/notes.md -in notes.txt
as bob;   check $B/fga get-document -bucket shared -key q4/notes.md -out bob-shared-notes.txt; check cmp notes.expected bob-shared-notes.txt
as alice; check $B/fga put-document -bucket shared -key q4/chat.log -in chat1.txt -collection
as alice; check $B/fga append -bucket shared -key q4/chat.log -in chat2.txt
as bob;   check $B/fga get-document -bucket shared -key q4/chat.log -out bob-shared-chat.txt; check cmp chat.expected bob-shared-chat.txt
echo "server mode: a document and an appended collection read by bob"
# Server-mode original files (S4b): encrypted under their own key and read
# only with raw-read and read on every unit, which bob lacks.
as alice; check $B/fga put-document -bucket shared -key q4/report.md -in notes.txt -original shared.bin
as alice; check $B/fga get-original -bucket shared -key q4/report.md -out shared-original.out; check cmp shared.bin shared-original.out
as bob;   if $B/fga get-original -bucket shared -key q4/report.md -out x.out 2>err.txt; then echo "UNEXPECTED: bob read the original"; exit 1; fi
echo "server-mode original: owner reads it; bob without raw-read: $(cat err.txt)"
# Server-mode derived outputs (S4b): the lineage is declared with the
# upload; bob, who may read the source, reads the output by policy alone,
# with no envelope or sharing step (compare the client-mode output above).
SHARED_SRC=$(echo "$SHARED_OUT" | awk '{print "storage.object:" $4 ":" $6}')
as alice; check $B/fga put -bucket shared -key q4/plan-summary.txt -in summary.txt -sources $SHARED_SRC
as bob;   check $B/fga get-derived -bucket shared -key q4/plan-summary.txt -out bob-summary.out; check cmp summary.txt bob-summary.out
echo "server-mode derived output: bob reads it through his own read of the source"
# Share grants (S5): carl, of another project, may not read alice's
# server-mode object until she grants him read and stat; the example
# bundle's rules honor grants on objects. Removing the grant, which is
# journaled, ends his access.
$ADMIN identity put -tenant t-acme -id carl -roles member -attrs '{"projects":["p2"]}'
$ADMIN grant -tenant t-acme -actor carl -preset storage
$B/fga keys init -dir carl > carl.keys
as carl;  if $B/fga get -bucket shared -key q4/plan.bin -out x.out 2>err.txt; then echo "UNEXPECTED: carl read without a grant"; exit 1; fi
as alice; check $B/fga grant -bucket shared -key q4/plan.bin -grantee carl -actions read,stat -expires 1h
as alice; check $B/fga grants -bucket shared -key q4/plan.bin
as carl;  check $B/fga get -bucket shared -key q4/plan.bin -out carl-shared.out; check cmp shared.bin carl-shared.out
as alice; check $B/fga ungrant -bucket shared -key q4/plan.bin -grantee carl
as carl;  if $B/fga get -bucket shared -key q4/plan.bin -out x.out 2>err.txt; then echo "UNEXPECTED: carl read after the grant was removed"; exit 1; fi
echo "share grant: carl reads alice's object only while granted; afterwards: $(cat err.txt)"
# The MCP role (R2 stretch M2): a generic MCP client reads through the
# same storage checks as the native API, for the user whose fga-mcp token
# it presents. Server-mode content comes back as plaintext, client-mode
# content not at all, and a session is bound to its user.
$ADMIN mcp enable -tenant t-acme
cat > mcp_lib.py <<'P'
import base64, json, sys, urllib.error, urllib.request
URL = "http://127.0.0.1:18446/mcp"
open_url = urllib.request.build_opener(urllib.request.ProxyHandler({})).open
def post(tok, body, sid=None, dlg=None):
    h = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if dlg:
        h["Fga-Delegation"] = dlg
    if sid:
        h.update({"Mcp-Session-Id": sid, "Mcp-Protocol-Version": "2025-06-18"})
    try:
        with open_url(urllib.request.Request(URL, data=json.dumps(body).encode(), headers=h, method="POST")) as r:
            raw = r.read()
            return r.status, r.headers.get("Mcp-Session-Id"), json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, None, None
def session(tok, recipient=None, dlg=None):
    caps = {"experimental": {"fga.encrypted-package": {"version": 1, "recipient": recipient}}} if recipient else {}
    st, sid, res = post(tok, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
                    "capabilities": caps, "clientInfo": {"name": "smoke", "version": "1"}}}, dlg=dlg)
    assert st == 200 and sid, ("initialize", st, res)
    post(tok, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, dlg)
    return sid
def rpc(tok, sid, method, params, dlg=None):
    st, _, res = post(tok, {"jsonrpc": "2.0", "id": 2, "method": method, "params": params}, sid, dlg)
    assert st == 200, (method, st)
    return res
P
cat > mcp_client.py <<'P'
exec(open("mcp_lib.py").read())
def read_doc(tok, sid):
    return rpc(tok, sid, "tools/call", {"name": "documents.read", "arguments": {"bucket": "shared", "key": "q4/notes.md"}})["result"]
bob, alice, carl, bobfp = sys.argv[1:5]
b = session(bob)
tools = sorted(t["name"] for t in rpc(bob, b, "tools/list", {})["result"]["tools"])
assert tools == ["documents.export", "documents.read", "documents.search", "text.read"], tools
doc = read_doc(bob, b)
assert not doc.get("isError") and doc["content"][0]["text"] == open("bob-shared-notes.txt").read().rstrip("\n"), doc
obj = rpc(bob, b, "resources/read", {"uri": "fga://shared/q4/plan.bin"})["result"]["contents"][0]
assert base64.b64decode(obj["blob"]) == open("shared.bin", "rb").read(), "the server-mode object differs"
print("MCP: bob reads a server-mode document and object as through the native API")
c = session(carl)
denied = read_doc(carl, c)
assert denied.get("isError") and "not found" in denied["content"][0]["text"], denied
print("MCP: carl, of another project:", denied["content"][0]["text"])
a = session(alice)
cm = rpc(alice, a, "resources/read", {"uri": "fga://reports/q3/report.bin"})
assert "error" in cm and "client-mode" in cm["error"]["message"], cm
print("MCP: a client-mode object is refused:", cm["error"]["message"][:60] + "...")
bp = session(bob, bobfp)
pk = rpc(bob, bp, "resources/read", {"uri": "fga://reports/q3/report.bin"})["result"]["contents"][0]
assert pk["mimeType"] == "application/vnd.fga.encrypted-package+json", pk.get("mimeType")
p = json.loads(pk["text"])
assert p["profile"] == "fga.encrypted-package/v1" and p["recipient"] == bobfp and len(base64.b64decode(p["object"]["ciphertext"])) > 3000000
print("MCP: a client declaring its recipient key gets the client-mode object as an encrypted package")
st, _, _ = post(alice, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}, b)
assert st == 403, ("alice in bob's session", st)
print("MCP: alice's token in bob's session:", st)
P
check python3 -I mcp_client.py "$(tok bob fga-mcp)" "$(tok alice fga-mcp)" "$(tok carl fga-mcp)" "$BOBFP"
# MCP authorization and transport rules: the protected resource metadata
# (RFC 9728), a 401 pointing to it, and a browser origin not allowed.
curl -sf http://127.0.0.1:18446/.well-known/oauth-protected-resource/mcp | grep -q '"resource":"http://127.0.0.1:18446/mcp"' \
  || { echo "SMOKE FAILED: protected resource metadata"; exit 1; }
curl -s -o /dev/null -D h401 -X POST http://127.0.0.1:18446/mcp; grep -qi 'resource_metadata=' h401 || { echo "SMOKE FAILED: 401 without resource_metadata"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Origin: http://rebound.example' -H "Authorization: Bearer $(tok bob fga-mcp)" http://127.0.0.1:18446/mcp)
[ "$code" = 403 ] || { echo "SMOKE FAILED: a foreign origin answered $code"; exit 1; }
echo "MCP: resource metadata served, 401 points to it, a foreign browser origin refused"
# A delegated agent (DLG-001): agent-7 acts for bob through the MCP role
# under a delegation that names agent-7, bob and the MCP workload; it reads
# what bob may read, and nothing without the delegation.
$ADMIN identity put -tenant t-acme -id agent-7 -roles agent
$ADMIN grant -tenant t-acme -actor agent-7 -preset storage
check $ADMIN delegation add -tenant t-acme -id dlg-bob -actor agent-7 -subject bob -audience local-dev -expires 1h \
  -grants 'agent.tool:discover,invoke;storage.bucket:list;storage.object:read,stat,discover;document.version:read-units,discover;document.text_unit:read'
cat > mcp_agent.py <<'P'
exec(open("mcp_lib.py").read())
agent, = sys.argv[1:2]
call = {"name": "documents.read", "arguments": {"bucket": "shared", "key": "q4/notes.md"}}
a = session(agent, dlg="dlg-bob")
doc = rpc(agent, a, "tools/call", call, "dlg-bob")["result"]
assert not doc.get("isError") and doc["content"][0]["text"] == open("bob-shared-notes.txt").read().rstrip("\n"), doc
own = session(agent)
assert rpc(agent, own, "tools/call", call)["result"].get("isError")
st, _, _ = post(agent, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}, a)
assert st == 403, ("the agent's session without its delegation", st)
print("MCP: agent-7 under dlg-bob reads bob's document as bob would; without the delegation, nothing; its session is bound to it")
P
check python3 -I mcp_agent.py "$(tok agent-7 fga-mcp)"
# The local bridge (M3): bob's application starts fga mcp-bridge and talks
# MCP over its stdin and stdout; the bridge opens client-mode packages
# with bob's keys, so the application reads plaintext the server never had.
cat > mcp_bridge.py <<'P'
import base64, json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp-bridge"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open("bridge.log", "wb"))
def send(m):
    p.stdin.write((json.dumps(m) + "\n").encode()); p.stdin.flush()
def recv(i):
    while True:
        line = p.stdout.readline()
        assert line, "the bridge closed its output; see bridge.log"
        m = json.loads(line)
        if m.get("id") == i:
            return m
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
      "clientInfo": {"name": "smoke-app", "version": "1"}}})
assert "result" in recv(1)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "fga://reports/q3/report.bin"}})
c = recv(2)["result"]["contents"][0]
assert base64.b64decode(c["blob"]) == open("plain.bin", "rb").read(), "the object differs"
send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "documents.read", "arguments": {"bucket": "reports", "key": "q3/notes.md"}}})
t = recv(3)["result"]
assert not t.get("isError") and t["content"][0]["text"] == open("notes.expected").read(), t
print("MCP bridge: bob's application reads his client-mode object and document as plaintext, opened by the bridge")
p.stdin.close()
p.wait(timeout=10)
P
as bob; check env FGA_MCP_URL=http://127.0.0.1:18446/mcp FGA_MCP_TOKEN="$(tok bob fga-mcp)" python3 -I mcp_bridge.py $B/fga
# The tools role (R2 executor): a registered tool is called on an external
# destination only once reviewed, for a member whom policy allows, exactly
# once per idempotency key, with the destination's own credential.
cat > destination.py <<'P'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open("destination.calls", "a") as f:
            f.write(json.dumps({"key": self.headers.get("Idempotency-Key"), "auth": self.headers.get("Authorization"),
                                "body": body.decode()}) + "\n")
        self.send_response(201); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 18447), H).serve_forever()
P
python3 -I destination.py & echo $! >> pids
echo "hooks-secret" > hooks.token
cat > tools.json <<J
{"version":1,"profile":"development","listen":"127.0.0.1:18448",$COMMON,"outbox_capacity":100000,"mcp_adapters":["local-dev"]}
J
cat > notify.json <<'J'
{"id":"notify","version":1,"description":"post a notification","destination":"hooks","endpoint":{"method":"POST","path":"/notify"},
 "arguments":[{"name":"message","type":"string","required":true,"max_length":200}],"max_hold_age":"1h"}
J
TOOLS="$B/fga-tools -config tools.json"
check $TOOLS tool add -tenant t-acme -file notify.json
check $TOOLS destination add -tenant t-acme -id hooks -url http://127.0.0.1:18447 -cidrs 127.0.0.0/8 -credential-file hooks.token -approved
$TOOLS > tools.log 2>&1 & echo $! >> pids
sleep 1
$ADMIN grant -tenant t-acme -actor bob -type network.destination -actions send
invoke() { curl -s -o invoke.out -w '%{http_code}' -H "Authorization: Bearer $(tok $1 fga-tools)" -H 'Content-Type: application/json' \
             -d "{\"tool\":\"notify\",\"version\":1,\"idempotency_key\":\"$2\",\"arguments\":{\"message\":\"$3\"}}" \
             http://127.0.0.1:18448/v1/invocations; }
code=$(invoke bob n-1 "before review"); [ "$code" = 404 ] || { echo "SMOKE FAILED: an unreviewed tool answered $code"; exit 1; }
check $TOOLS tool review -tenant t-acme -id notify
code=$(invoke bob n-1 "build finished"); [ "$code" = 200 ] && grep -q '"state":"SUCCEEDED"' invoke.out || { echo "SMOKE FAILED: invoke $code $(cat invoke.out)"; exit 1; }
first=$(python3 -I -c 'import json;print(json.load(open("invoke.out"))["invocation_id"])')
code=$(invoke bob n-1 "build finished"); [ "$code" = 200 ] && grep -q "$first" invoke.out || { echo "SMOKE FAILED: retry $code $(cat invoke.out)"; exit 1; }
[ "$(wc -l < destination.calls | tr -d ' ')" = 1 ] && grep -q "\"key\": \"$first\"" destination.calls && grep -q "Bearer hooks-secret" destination.calls \
  || { echo "SMOKE FAILED: the destination got $(cat destination.calls)"; exit 1; }
$ADMIN identity put -tenant t-acme -id gus -roles guest -attrs '{"projects":["p1"]}'
code=$(invoke gus g-1 "hello"); [ "$code" = 404 ] || { echo "SMOKE FAILED: a guest's call answered $code"; exit 1; }
echo "tools role: a reviewed tool called once for bob ($first), its retry answered without a second call, a guest refused"
# The tools role through the MCP role (E2): bob's MCP client lists the
# registered tool and calls it; the tools role decides it for bob.
cat > mcp_tools.py <<'P'
exec(open("mcp_lib.py").read())
bob, gus = sys.argv[1:3]
b = session(bob)
tools = {t["name"]: t for t in rpc(bob, b, "tools/list", {})["result"]["tools"]}
assert tools["tool.notify"]["inputSchema"]["properties"]["version"]["const"] == 1, sorted(tools)
call = {"name": "tool.notify", "arguments": {"version": 1, "idempotency_key": "m-1", "arguments": {"message": "via MCP"}}}
r = rpc(bob, b, "tools/call", call)["result"]
assert not r.get("isError") and r["structuredContent"]["state"] == "SUCCEEDED", r
g = session(gus)
assert "tool.notify" not in [t["name"] for t in rpc(gus, g, "tools/list", {})["result"]["tools"]]
assert rpc(gus, g, "tools/call", call)["result"].get("isError")
print("MCP: bob lists tool.notify and calls it through the MCP role:", r["content"][0]["text"], "- a guest sees and calls nothing")
P
check python3 -I mcp_tools.py "$(tok bob fga-mcp)" "$(tok gus fga-mcp)"
[ "$(wc -l < destination.calls | tr -d ' ')" = 2 ] && grep -q "via MCP" destination.calls || { echo "SMOKE FAILED: MCP call $(cat destination.calls)"; exit 1; }
# Final removal of a server-mode version destroys its data key (S6,
# SSE-006): reclaim retires the withdrawn version and reports that backups
# taken before still hold the key.
as alice; DRAFT_OUT=$($B/fga put -bucket shared -key q4/draft.txt -in summary.txt) || { echo "SMOKE FAILED: draft put"; exit 1; }
as alice; check $B/fga put -bucket shared -key q4/draft.txt -in notes.txt
as alice; check $B/fga rm -bucket shared -key q4/draft.txt -version "$(echo "$DRAFT_OUT" | awk '{print $6}')"
RECLAIM_OUT=$($ADMIN reclaim) || { echo "SMOKE FAILED: reclaim"; exit 1; }; echo "$RECLAIM_OUT"
echo "$RECLAIM_OUT" | grep -q "destroyed 1 server-mode data keys" || { echo "SMOKE FAILED: reclaim destroyed no data key"; exit 1; }


# Audit export as a signed hash chain (AUD-002, AUD-003): the export key
# signs each file's link, the catalog keeps the chain head.
AUDITPUB=$($ADMIN audit-key generate -out audit.key | awk '/^public key/ {print $NF}')
check $ADMIN audit export -dir audit -key audit.key
$ADMIN backup -backup-key backup.key -out backup1
as alice; $B/fga rm -bucket reports -key q3/report.bin
as alice; if $B/fga get -bucket reports -key q3/report.bin -out x.out 2>/dev/null; then echo "UNEXPECTED: read after delete"; exit 1; fi; echo "deleted"
$ADMIN recipient revoke -tenant t-acme -fingerprint $BOBFP
check $ADMIN audit export -dir audit -key audit.key
$ADMIN restore -backup-key backup.key -from backup1
as alice; if $B/fga get -bucket reports -key q3/report.bin -out x.out 2>err.txt; then echo "UNEXPECTED: read while admission closed"; exit 1; fi; echo "while closed: $(cat err.txt)"
# The restored catalog holds server-mode data keys: reconcile checks them
# against the KEK ring, kept apart from backups (SSE-006), and refuses to
# reopen admission without it.
if $ADMIN reconcile 2>err.txt; then echo "UNEXPECTED: reconcile without the KEK ring"; exit 1; fi; echo "reconcile without the KEK ring: $(cat err.txt)"
$ADMIN reconcile -kek-file keks
as alice; $B/fga get -bucket reports -key q3/report.bin -out alice2.out && cmp plain.bin alice2.out && echo "restored object readable by alice"
as bob;   check $B/fga get -bucket shared -key q4/plan.bin -out bob-restored.out; check cmp shared.bin bob-restored.out
echo "restored server-mode object readable by bob"
as bob;   if $B/fga get -bucket reports -key q3/report.bin -out x.out 2>err.txt; then echo "UNEXPECTED: revoked bob read"; exit 1; fi; echo "bob after restore (key revoked after backup): $(cat err.txt)"
psql -h localhost -d $DB -Atc "select kind, count(*) from audit_outbox group by kind order by kind"
check $ADMIN audit export -dir audit -key audit.key
echo "audit events exported: $(cat audit/*.jsonl | wc -l | tr -d ' ') lines, $(cat audit/*.jsonl | python3 -I -c 'import sys,json;print(len({json.loads(l)["id"] for l in sys.stdin}))') unique"
# The chain continues across the restore: checked against the catalog's
# head, and offline with the public key alone.
check $ADMIN audit verify -dir audit -public-key "$AUDITPUB"
check env -u FGA_DATABASE_URL $B/fga-admin audit verify -dir audit -public-key "$AUDITPUB"
check $ADMIN audit status -capacity 100000
echo SMOKE PASSED
