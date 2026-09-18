#!/usr/bin/env bash
# Pinned-source software-boot test kernel. Not an approved SNP deployment kernel.
set -euo pipefail
output="${1:?new output directory required}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
version=6.12.110
archive="$output/linux-$version.tar.xz"
curl --fail --location --retry 3 "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$version.tar.xz" -o "$archive"
echo "8cee19e1839bb6ff4d5254d761933ae6ab670492d5ed030e09a80538320d5c4c  $archive" | sha256sum --check
tar -xJf "$archive" -C "$output"
cd "$output/linux-$version"
export KBUILD_BUILD_TIMESTAMP='2026-09-18 00:00:00 UTC'
export KBUILD_BUILD_USER=wcm KBUILD_BUILD_HOST=boot-test KBUILD_BUILD_VERSION=1
make ARCH=x86_64 tinyconfig
# All boot-critical drivers are built in; no module loader or external root.
enabled="64BIT PRINTK MULTIUSER BINFMT_ELF TTY SERIAL_8250 SERIAL_8250_CONSOLE
SYSFS TMPFS DEVTMPFS BLK_DEV_INITRD PCI ACPI FW_CFG_SYSFS
NET INET UNIX NETDEVICES ETHERNET NET_VENDOR_INTEL E1000 IP_PNP
FUTEX EPOLL EVENTFD SIGNALFD TIMERFD POSIX_TIMERS SYSCTL
ADVISE_SYSCALLS FILE_LOCKING EFI EFI_STUB RELOCATABLE CPU_SUP_AMD
AMD_MEM_ENCRYPT SEV_GUEST"
disabled="MODULES DEVMEM DEVKMEM KEXEC KEXEC_FILE USER_NS BINFMT_MISC COREDUMP SWAP UEVENT_HELPER"
for option in $enabled; do scripts/config --enable "$option"; done
for option in $disabled; do scripts/config --disable "$option"; done
make ARCH=x86_64 olddefconfig
for option in $enabled; do
  grep -qx "CONFIG_$option=y" .config || { echo "Required built-in missing: $option"; exit 1; }
done
for option in $disabled; do
  if grep -q "^CONFIG_$option=[ym]" .config; then echo "Forbidden feature: $option"; exit 1; fi
done
make ARCH=x86_64 -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "$output/bzImage"
cp .config "$output/kernel.config"
cc --version > "$output/toolchain.txt"
ld --version >> "$output/toolchain.txt"
sha256sum "$output/bzImage" "$output/kernel.config" > "$output/kernel-digests.txt"
