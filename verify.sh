#!/bin/sh
# Checks a SudoWhizzy agent release against this source.
#
#   sh verify.sh            checks the release sudowhizzy.com serves right now
#   sh verify.sh /usr/local/bin/sudowhizzy-agent
#                           also checks the binary installed on this machine
#
# What it does: downloads the release manifest and its signature, verifies the
# signature with release-key.pem (the key built into every agent), checks out
# the commit the manifest names, builds the agent with the same Go flags and
# compares the SHA-256 of the result with the manifest's. Needs git, curl,
# openssl and the Go version the manifest names (go.dev/dl); a different Go
# version gives a different hash, which proves nothing either way.
set -eu
HUB="${HUB:-https://sudowhizzy.com}"
cd "$(dirname "$0")"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

curl -fsSL "$HUB/dl/manifest.json" -o "$T/manifest.json"
curl -fsSL "$HUB/dl/manifest.sig" | base64 -d > "$T/manifest.sig"
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in "$T/manifest.json" -sigfile "$T/manifest.sig" >/dev/null \
  && echo "signature: valid (release-key.pem)" || { echo "signature: DOES NOT MATCH"; exit 1; }

field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$T/manifest.json"; }
VERSION=$(field version); COMMIT=$(field commit); GO=$(field go)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
WANT=$(sed -n "s/.*\"$ARCH\":\"\([0-9a-f]*\)\".*/\1/p" "$T/manifest.json")
echo "release: $VERSION, commit $COMMIT, built with $GO"
echo "have: $(go version)"

git fetch -q origin "$COMMIT" 2>/dev/null || true
git -c advice.detachedHead=false checkout -q "$COMMIT"
CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -buildvcs=false -ldflags="-s -w -X main.sourceCommit=$COMMIT" -o "$T/agent" .
GOT=$(sha256sum "$T/agent" | cut -d' ' -f1)
if [ "$GOT" = "$WANT" ]; then echo "build: the source at $COMMIT gives exactly the released $ARCH binary ($GOT)"
else echo "build: MISMATCH, built $GOT, manifest says $WANT (same Go version? $GO)"; exit 1; fi

if [ "${1:-}" ]; then
  HAVE=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$HAVE" = "$WANT" ]; then echo "installed: $1 is this release"
  else echo "installed: $1 is NOT this release ($HAVE); it may be an older version waiting to update, check with: $1 build"; exit 1; fi
fi
