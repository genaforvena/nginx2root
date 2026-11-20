#!/bin/sh
# Provision nginx sources for the CVE-2026-123007 lab.
# Fetches and verifies the two pinned release tarballs, then extracts them
# under lab/nginx-src/. Provisioning only: no build happens here.
set -eu

cd "$(dirname "$0")"

# tag   tarball sha256 (nginx.org, verified 2026-11-20)
# release-1.31.8 (git e429960d11c75b4db149fc362dd9ddd4d52b3b3d, affected)
# release-1.31.9 (git a1cca947c70cbcfe210aa1c4b56dae4332cbd0c4, fixed/control)
set -- \
  1.31.8 0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1 \
  1.31.9 a11c5eeee2e257f4478f0e649f84b0040787d277d2d3e5233952aa6b6dcb80ad

mkdir -p src nginx-src

while [ $# -gt 0 ]; do
  ver=$1; want=$2; shift 2
  tb="src/nginx-$ver.tar.gz"
  if [ ! -f "$tb" ]; then
    echo "fetching nginx-$ver.tar.gz" >&2
    curl -sSf --retry 3 -o "$tb" "https://nginx.org/download/nginx-$ver.tar.gz"
  fi
  got=$(sha256sum "$tb" | awk '{print $1}')
  if [ "$got" != "$want" ]; then
    echo "sha256 mismatch for $tb: got $got want $want" >&2
    exit 1
  fi
  echo "$tb sha256 OK ($got)"
  if [ ! -d "nginx-src/nginx-$ver" ]; then
    tar -xzf "$tb" -C nginx-src/
  fi
  echo "extracted nginx-src/nginx-$ver"
done

# --- gitignored lab corpus + TLS cert (idempotent; see report repro plan) ---
mkdir -p corpus ssl
if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
  echo "generating ssl/cert.pem + ssl/key.pem (throwaway lab cert)" >&2
  openssl req -x509 -newkey rsa:2048 -keyout ssl/key.pem -out ssl/cert.pem \
    -days 3650 -nodes -subj "/CN=localhost" >/dev/null 2>&1
fi
if [ ! -f corpus/blob ]; then
  echo "generating corpus/blob (64 MiB urandom)" >&2
  dd if=/dev/urandom of=corpus/blob bs=1M count=64 status=none
fi
# Canary corpus for the Stage-A-mechanics grooming slice: 16 MiB of
# 32-byte records, magic(8) + reserved(4) + LE record-index(8) + pad(12),
# so any surviving or partial record in a dumped window resolves to its
# exact file offset. Regenerate deterministically (committed generator:
# lab/harness/xgroom-verify.py --make-canary).
if [ ! -f corpus/canary ]; then
  echo "generating corpus/canary (16 MiB records)" >&2
  python3 harness/xgroom-verify.py --make-canary corpus/canary
fi
echo "corpus: $(ls corpus)"
echo "provisioned: $(ls nginx-src)"
