"""Instrument an already patched firmware tree for TCG tests ONLY.

Never use this image for custody: its launch table comes from untrusted fw_cfg.
Production firmware is built and copied before this separate transformation.
"""
import argparse
import hashlib
import json
from pathlib import Path

import firmware_profile as profile

INJECTION = r'''
  // TEST ONLY: synthetic launch state, with no hardware authentication.
  {
    FIRMWARE_CONFIG_ITEM Item;
    UINTN FixtureSize;
    if (!EFI_ERROR (QemuFwCfgFindFile ("opt/wcm/test-hashes", &Item, &FixtureSize)) &&
        (FixtureSize == 176)) {
      QemuFwCfgSelectItem (Item);
      QemuFwCfgReadBytes (FixtureSize, Ptr);
    }
  }
'''

SETUP = r'''
  // TEST ONLY: TCG's QEMU rewrites Linux setup bytes; SEV delivery does not.
  // Restore bytes from the actual supplied test kernel before verification.
  // This is transport emulation, not a trusted firmware input path.
  if (!EFI_ERROR (FetchStatus) && (Blob != NULL) && (StrCmp (FileName, L"kernel") == 0)) {
    FIRMWARE_CONFIG_ITEM Item;
    UINTN FixtureSize;
    if (EFI_ERROR (QemuFwCfgFindFile ("opt/wcm/test-setup", &Item, &FixtureSize)) ||
        (FixtureSize == 0) || (FixtureSize > 8192) || (FixtureSize > Blob->Size)) {
      __asm__ __volatile__ ("outl %0, %w1" : : "a" (19), "Nd" ((UINT16)0xf4));
      CpuDeadLoop ();
    }
    QemuFwCfgSelectItem (Item);
    QemuFwCfgReadBytes (FixtureSize, Blob->Data);
  }
'''


def exit_vm(code):
    # GCC-only test build. isa-debug-exit returns (value << 1) | 1.
    return f'__asm__ __volatile__ ("outl %0, %w1" : : "a" ({code}), "Nd" ((UINT16)0xf4)); CpuDeadLoop ();'


def apply(source, receipt):
    expected = json.loads(receipt.read_text())["patched_sources"]
    for name, digest in expected.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != digest:
            raise ValueError("test fixture requires exact candidate source")
    path = source / profile.VERIFIER
    text = path.read_text()
    text = text.replace('#include <Library/BaseLib.h>',
                        '#include <Library/BaseLib.h>\n#include <Library/QemuFwCfgLib.h>')
    text = text.replace('  Size = FixedPcdGet32 (PcdQemuHashTableSize);',
                        '  Size = FixedPcdGet32 (PcdQemuHashTableSize);\n' + INJECTION)
    for name, code in (("BlobVerifierLibSevHashesConstructor", 17), ("VerifyBlob", 18)):
        start, _, end = profile.function_span(text, name)
        text = text[:start] + text[start:end].replace("CpuDeadLoop ();", exit_vm(code)) + text[end:]
    path.write_bytes(text.encode())
    inf = path.with_name("BlobVerifierLibSevHashes.inf")
    inf.write_bytes(inf.read_text().replace("[LibraryClasses]", "[LibraryClasses]\n  QemuFwCfgLib").encode())
    path = source / profile.LOADER
    text = path.read_text()
    anchor = "  Blob   = FindKernelBlob (FileName);"
    if text.count(anchor) != 1:
        raise ValueError("kernel fixture anchor changed")
    text = text.replace(anchor, anchor + "\n" + SETUP)
    start, _, end = profile.function_span(text, "QemuKernelFetchNamedBlobs")
    text = text[:start] + text[start:end].replace("return EFI_ACCESS_DENIED;",
        '''{
      CONST CHAR8 *Marker = "WCM_TEST_NAMED_DENY\\n";
      while (*Marker != '\\0') {
        __asm__ __volatile__ ("outb %0, %w1" : : "a" ((UINT8)*Marker), "Nd" ((UINT16)0x402));
        Marker++;
      }
    }
    return EFI_ACCESS_DENIED;''') + text[end:]
    path.write_bytes(text.encode())
    path = source / profile.MANAGER
    path.write_bytes(path.read_text().replace("CpuDeadLoop ();", exit_vm(20)).encode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    apply(args.source, args.receipt)
