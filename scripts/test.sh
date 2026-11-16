#!/bin/bash

# Run all project tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/.." && pwd))"

echo "Running secure memory and session cleanup tests..."
make -C "$REPO_ROOT/components/secure_memory/test" run

echo "Running deflate_codec tests..."
make -C "$REPO_ROOT/components/deflate_codec/test" run

echo "Running bbqr tests..."
make -C "$REPO_ROOT/components/bbqr/test" run

echo "Running QR parser tests..."
make -C "$REPO_ROOT/main/qr/test" run

# bip138 and the core PSBT tests link the host mbedTLS; a machine without
# libmbedtls-dev (psa/crypto.h + -lmbedcrypto) cannot build them.  Say so
# instead of failing the whole suite.
HAVE_HOST_MBEDTLS=0
if echo '#include <psa/crypto.h>' | ${CC:-cc} -E - >/dev/null 2>&1 &&
   echo 'int main(void){return 0;}' | ${CC:-cc} -x c - -lmbedcrypto         -o /dev/null >/dev/null 2>&1; then
  HAVE_HOST_MBEDTLS=1
fi

if [ "$HAVE_HOST_MBEDTLS" = 1 ]; then
  echo "Running bip138 tests..."
  make -C "$REPO_ROOT/components/bip138" run

  echo "Running core tests..."
  make -C "$REPO_ROOT/main/core/test" run
else
  echo "SKIP bip138/core tests: host mbedTLS not found (install libmbedtls-dev)"
fi

echo "Running k_quirc tests..."
K_QUIRC_TEST_DIR="$REPO_ROOT/components/k_quirc/test"
# Keep the CMake tree out of the submodule when the caller has a build root.
K_QUIRC_TEST_BUILD="${KERN_NEXUS_BUILD:-$K_QUIRC_TEST_DIR/build}/k_quirc-test"
cmake -S "$K_QUIRC_TEST_DIR" -B "$K_QUIRC_TEST_BUILD" -DK_QUIRC_SANITIZE=OFF
cmake --build "$K_QUIRC_TEST_BUILD" --parallel
ctest --test-dir "$K_QUIRC_TEST_BUILD" --output-on-failure

echo "All tests passed!"
