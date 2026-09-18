#!/usr/bin/env bash
# Provisional candidate firmware. Same-runner repetition is not build approval.
set -euo pipefail
output="${1:?new output directory required}"
mkdir "$output"
output="$(cd "$output" && pwd)"
scripts="$(cd "$(dirname "$0")" && pwd)"
revision=2970e5699ba6267f3384ffab20f96647578aebc8
git -c core.autocrlf=false clone --quiet --no-checkout --depth 1 \
  --branch edk2-stable202608 https://github.com/tianocore/edk2.git "$output/source"
cd "$output/source"
test "$(git rev-parse HEAD)" = "$revision"
git checkout --detach "$revision"
git submodule update --init --depth 1 \
  CryptoPkg/Library/OpensslLib/openssl \
  MdeModulePkg/Library/BrotliCustomDecompressLib/brotli \
  BaseTools/Source/C/BrotliCompress/brotli \
  MdePkg/Library/MipiSysTLib/mipisyst
git submodule status > "$output/submodules.txt"
python "$scripts/firmware_controls.py" "$PWD" "$output/native-controls.json"
python "$scripts/firmware_profile.py" "$PWD" > "$output/profile.json"
git diff --binary > "$output/profile.patch"
export SOURCE_DATE_EPOCH=1789689600
export PYTHON_COMMAND=python3
make -C BaseTools -j"$(nproc)"
set +u
source edksetup.sh --reconfig
set -u
options=(-a X64 -t GCC -b RELEASE -p OvmfPkg/AmdSev/AmdSevX64.dsc
  -D SOURCE_DEBUG_ENABLE=FALSE -D BUILD_SHELL=FALSE -D DEBUG_TO_MEM=FALSE
  -D FD_SIZE_IN_KB=4096 -n "$(nproc)")
build "${options[@]}" -y "$output/build-report.txt" -Y LIBRARY -Y PCD
cp Build/AmdSev/RELEASE_GCC/FV/OVMF.fd "$output/OVMF.fd"
build "${options[@]}" cleanall
build "${options[@]}"
cmp "$output/OVMF.fd" Build/AmdSev/RELEASE_GCC/FV/OVMF.fd
{
  cc --version
  ld --version
  nasm --version
  python --version
  python -m pip freeze
} > "$output/toolchain.txt"
cd "$output"
sha256sum OVMF.fd profile.json profile.patch > firmware-digests.txt
echo 'Restricted firmware repeated byte-for-byte on one runner; hardware validation remains false.'
