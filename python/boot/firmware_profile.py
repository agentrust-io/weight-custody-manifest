"""Apply the provisional direct-boot-only profile to exact pinned edk2 sources."""
import argparse
import hashlib
import json
from pathlib import Path

REVISION = "2970e5699ba6267f3384ffab20f96647578aebc8"
ROOT = Path(__file__).parent
VERIFIER = "OvmfPkg/AmdSev/BlobVerifierLibSevHashes/BlobVerifierSevHashes.c"
LOADER = "OvmfPkg/QemuKernelLoaderFsDxe/QemuKernelLoaderFsDxe.c"
MANAGER = "OvmfPkg/Library/PlatformBootManagerLib/BdsPlatform.c"
DSC = "OvmfPkg/AmdSev/AmdSevX64.dsc"
FDF = "OvmfPkg/AmdSev/AmdSevX64.fdf"


def function_span(source, name):
    """Locate a function in these pinned sources, not a general C parser."""
    start = source.index("\n" + name + " (") + 1
    opening = source.index("\n{", start) + 1
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return start, opening, end


def body(source, name, replacement):
    _, opening, end = function_span(source, name)
    return source[:opening] + "{\n" + replacement.strip() + "\n}" + source[end:]


CONSTRUCTOR = r'''
  HASH_TABLE       *Ptr;
  HASH_TABLE       *Entry;
  UINT32           Size;
  UINTN            Index;
  CONST EFI_GUID   *Expected[3] = {
    &mSevCmdlineHashGuid, &mSevInitrdHashGuid, &mSevKernelHashGuid
  };

  mHashesTable     = NULL;
  mHashesTableSize = 0;
  Ptr  = (void *)(UINTN)FixedPcdGet64 (PcdQemuHashTableBase);
  Size = FixedPcdGet32 (PcdQemuHashTableSize);
  // Require QEMU's complete, canonical three-entry table before exposing blobs.
  if ((Ptr == NULL) || (Size < 168) ||
      !CompareGuid (&Ptr->Guid, &SEV_HASH_TABLE_GUID) || (Ptr->Len != 168)) {
    CpuDeadLoop ();
    return RETURN_SUCCESS;
  }
  for (Index = 0; Index < 3; ++Index) {
    Entry = (HASH_TABLE *)(Ptr->Data + Index * 50);
    if ((Entry->Len != 50) || !CompareGuid (&Entry->Guid, Expected[Index])) {
      CpuDeadLoop ();
      return RETURN_SUCCESS;
    }
  }
  mHashesTable = (HASH_TABLE *)Ptr->Data;
  mHashesTableSize = 150;
  return RETURN_SUCCESS;
'''

NAMED = r'''
  struct {
    UINT32    FileSize;
    UINT16    FileSelect;
    UINT16    Reserved;
    CHAR8     FileName[QEMU_FW_CFG_FNAME_SIZE];
  } Entry;
  UINT32 Count;
  UINT32 Index;

  QemuFwCfgSelectItem (QemuFwCfgItemFileDir);
  Count = SwapBytes32 (QemuFwCfgRead32 ());
  if (Count > 4096) {
    return EFI_ACCESS_DENIED;
  }
  for (Index = 0; Index < Count; ++Index) {
    QemuFwCfgReadBytes (sizeof Entry, &Entry);
    // All named boot payloads, including shim and named kernel overrides, are
    // outside this profile. Unrelated fw_cfg configuration remains available.
    if (CompareMem (Entry.FileName, "etc/boot/", 9) == 0) {
      return EFI_ACCESS_DENIED;
    }
  }
  return EFI_SUCCESS;
'''

IGVM = r'''
  // This profile only admits the three verified traditional fw_cfg blobs.
  if (GetFirstGuidHob (&gEfiIgvmDataHobGuid) != NULL) {
    return EFI_ACCESS_DENIED;
  }
  return EFI_SUCCESS;
'''

BEFORE = r'''
  // Transfer before generic BDS hotkeys, DriverOrder, BootNext or BootOrder.
  VisitAllInstancesOfProtocol (
    &gEfiPciRootBridgeIoProtocolGuid, ConnectRootBridge, NULL
    );
  EfiEventGroupSignal (&gRootBridgesConnectedEventGroupGuid);
  EfiEventGroupSignal (&gEfiEndOfDxeEventGroupGuid);
  PciAcpiInitialization ();
  TryRunningQemuKernel ();
  // Missing, rejected or returning kernels never enter another boot path.
  CpuDeadLoop ();
'''


def transform(sources):
    result = dict(sources)
    verifier = body(result[VERIFIER], "BlobVerifierLibSevHashesConstructor", CONSTRUCTOR)
    start, _, end = function_span(verifier, "VerifyBlob")
    function = verifier[start:end]
    function = function.replace("  return EFI_SUCCESS;", "  CpuDeadLoop ();\n  return EFI_ACCESS_DENIED;")
    function = function.replace("    Sha256HashAll (Buf, BufSize, Hash);",
        "    if (!Sha256HashAll (Buf, BufSize, Hash)) {\n      CpuDeadLoop ();\n      return EFI_ACCESS_DENIED;\n    }")
    result[VERIFIER] = verifier[:start] + function + verifier[end:]
    result[LOADER] = body(body(result[LOADER], "QemuKernelFetchNamedBlobs", NAMED),
                          "QemuKernelRegisterIgvmBlobs", IGVM)
    result[MANAGER] = body(result[MANAGER], "PlatformBootManagerBeforeConsole", BEFORE)
    for name in ("PlatformBootManagerAfterConsole", "PlatformBootManagerUnableToBoot"):
        result[MANAGER] = body(result[MANAGER], name, "  CpuDeadLoop ();")
    # Remove executable fallback payloads, not merely their menu entries.
    for name in (DSC, FDF):
        result[name] = "\n".join(line for line in result[name].split("\n")
            if "OvmfPkg/AmdSev/Grub/" not in line
            and "ShellComponents.dsc.inc" not in line and "ShellDxe.fdf.inc" not in line
            and "MdeModulePkg/Application/BootManagerMenuApp/" not in line)
    return result


def apply(source):
    lock = json.loads((ROOT / "firmware-source.json").read_text(encoding="utf-8"))
    originals = {name: (source / name).read_bytes() for name in lock["sources"]}
    hashes = {name: hashlib.sha256(value).hexdigest() for name, value in originals.items()}
    if lock["revision"] != REVISION or hashes != lock["sources"]:
        raise ValueError("firmware source differs from pinned upstream bytes")
    patched = transform({name: value.decode("utf-8") for name, value in originals.items()})
    for name, value in patched.items():
        (source / name).write_bytes(value.encode("utf-8"))
    return {"kind": "wcm/restricted-firmware-source/v1", "revision": REVISION,
            "provisional": True, "hardware_validated": False,
            "patched_sources": {name: hashlib.sha256(value.encode()).hexdigest()
                                for name, value in patched.items()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    print(json.dumps(apply(args.source), indent=2, sort_keys=True))
