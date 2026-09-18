"""Compile and execute actual firmware C with simulated UEFI services.

This checks selected control flow, not a VM, SNP hardware or all DXE consumers.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

import firmware_profile as profile

HEADER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <openssl/sha.h>
typedef uint8_t UINT8; typedef uint16_t UINT16; typedef uint32_t UINT32;
typedef uint64_t UINT64; typedef uintptr_t UINTN; typedef int32_t INT32;
typedef uint16_t CHAR16; typedef char CHAR8;
typedef int EFI_STATUS; typedef int RETURN_STATUS;
typedef struct {UINT32 a; UINT16 b,c; UINT8 d[8];} GUID;
typedef GUID EFI_GUID;
#define VOID void
#define CONST const
#define STATIC static
#define IN
#define EFIAPI
#define EFI_SUCCESS 0
#define EFI_ACCESS_DENIED 1
#define RETURN_SUCCESS 0
#define EFI_ERROR(s) ((s)!=0)
#define DEBUG(x) ((void)0)
#define SHA256_DIGEST_SIZE 32
#define FixedPcdGet64(x) ((UINTN)area)
#define FixedPcdGet32(x) area_size
static unsigned char area[176]; static unsigned area_size=176;
static jmp_buf jump;
static int hash_failure;
static void CpuDeadLoop(void) {longjmp(jump,1);}
static int CompareGuid(const GUID *a,const GUID *b) {return !memcmp(a,b,16);}
static int CompareMem(const void *a,const void *b,size_t n) {return memcmp(a,b,n);}
static int StrCmp(const CHAR16 *a,const CHAR16 *b) {while(*a && *a==*b){a++;b++;}return *a-*b;}
static int Sha256HashAll(const void *p,size_t n,void *out) {
  if(hash_failure)return 0; return SHA256(p,n,out)!=NULL;
}
'''

VERIFIER_MAIN = r'''
int main(int argc,char **argv) {
  if(argc!=2)return 90;
  const char *mode=argv[1];
  HASH_TABLE *table=(HASH_TABLE *)area;
  GUID guid=SEV_HASH_TABLE_GUID;
  memcpy(&table->Guid,&guid,16); table->Len=168;
  const GUID *guids[]={&mSevCmdlineHashGuid,&mSevInitrdHashGuid,&mSevKernelHashGuid};
  for(int i=0;i<3;i++) {
    HASH_TABLE *e=(HASH_TABLE *)(table->Data+i*50);
    memcpy(&e->Guid,guids[i],16); e->Len=50;
    SHA256((const unsigned char *)"payload",7,e->Data);
  }
  if(!strcmp(mode,"missing"))table->Len=118;
  if(!strcmp(mode,"duplicate"))memcpy(table->Data+100,&mSevCmdlineHashGuid,16);
  if(!strcmp(mode,"order"))memcpy(table->Data,&mSevKernelHashGuid,16);
  if(!strcmp(mode,"zero-length"))((HASH_TABLE *)table->Data)->Len=0;
  if(!strcmp(mode,"oversized-entry"))((HASH_TABLE *)table->Data)->Len=65535;
  if(!strcmp(mode,"truncated"))area_size=167;
  if(!strcmp(mode,"absent"))memset(area,0,sizeof(area));
  if(!strcmp(mode,"hash-failure"))hash_failure=1;
  if(setjmp(jump)){puts("STOP");return 0;}
  BlobVerifierLibSevHashesConstructor();
  const CHAR16 *name=(const CHAR16 *)L"kernel";
  if(!strcmp(mode,"initrd"))name=(const CHAR16 *)L"initrd";
  if(!strcmp(mode,"cmdline"))name=(const CHAR16 *)L"cmdline";
  if(!strcmp(mode,"unknown"))name=(const CHAR16 *)L"shim";
  const char *payload=!strcmp(mode,"tamper")?"changed":"payload";
  EFI_STATUS s=VerifyBlob(name,payload,7,!strcmp(mode,"fetch-failure"));
  puts(s==EFI_SUCCESS?"ALLOW":"DENY");return 0;
}
'''

ROUTE_HEADER = r'''
#define QEMU_FW_CFG_FNAME_SIZE 56
#define QemuFwCfgItemFileDir 1
static UINT32 count,cursor; static unsigned char directory[3][64];
static int hob,loads,events,visits,pci,transfer;
static int gEfiIgvmDataHobGuid,gEfiPciRootBridgeIoProtocolGuid;
static int gRootBridgesConnectedEventGroupGuid,gEfiEndOfDxeEventGroupGuid;
static void ConnectRootBridge(void){}
static UINT32 SwapBytes32(UINT32 x){return __builtin_bswap32(x);}
static void QemuFwCfgSelectItem(int x){(void)x;cursor=0;}
static UINT32 QemuFwCfgRead32(void){return SwapBytes32(count);}
static void QemuFwCfgReadBytes(UINTN n,void *p){
  if(n!=64 || cursor>=3)exit(91);memcpy(p,directory[cursor++],64);
}
static void *GetFirstGuidHob(void *guid){(void)guid;return hob?&hob:NULL;}
static void VisitAllInstancesOfProtocol(void *a,void (*b)(void),void *c){
  (void)a;(void)b;(void)c;visits++;
}
static void EfiEventGroupSignal(void *p){(void)p;events++;}
static void PciAcpiInitialization(void){pci++;}
static int TryRunningQemuKernel(void){loads++;if(transfer)longjmp(jump,2);return transfer;}
'''

ROUTE_MAIN = r'''
int main(int argc,char **argv){
  if(argc!=2)return 90;const char *mode=argv[1];
  if(!strncmp(mode,"named-",6)){
    count=3;
    for(int i=0;i<3;i++)strcpy((char *)directory[i]+8,"opt/wcm/config");
    int index=mode[6]-'0'; if(index<0 || index>2)return 90;
    strcpy((char *)directory[index]+8,"etc/boot/shim");
  } else if(!strcmp(mode,"unrelated")){
    count=1;strcpy((char *)directory[0]+8,"opt/wcm/config");
  } else if(!strcmp(mode,"too-many")){count=4097;}
  if(!strncmp(mode,"named-",6)||!strcmp(mode,"unrelated")||!strcmp(mode,"too-many")||!strcmp(mode,"empty")){
    puts(QemuKernelFetchNamedBlobs()==EFI_SUCCESS?"ALLOW":"DENY");return 0;
  }
  if(!strncmp(mode,"igvm",4)){
    hob=!strcmp(mode,"igvm-present");
    puts(QemuKernelRegisterIgvmBlobs()==EFI_SUCCESS?"ALLOW":"DENY");return 0;
  }
  transfer=!strcmp(mode,"transfer")?1:(!strcmp(mode,"kernel-error")?-1:0);
  // Only the transfer case simulates control never returning from the kernel.
  if(transfer==-1)transfer=0;
  int state=setjmp(jump);
  if(state){printf("%s:%d:%d:%d:%d\n",state==2?"TRANSFER":"STOP",loads,events,visits,pci);return 0;}
  if(!strcmp(mode,"after"))PlatformBootManagerAfterConsole();
  else if(!strcmp(mode,"unable"))PlatformBootManagerUnableToBoot();
  else PlatformBootManagerBeforeConsole();
  puts("RETURNED");return 0;
}
'''


def extract(source, name, result_type):
    start, _, end = profile.function_span(source, name)
    return result_type + "\n" + source[start:end] + "\n"


def compile_c(directory, name, code):
    src, exe = directory / (name + ".c"), directory / name
    src.write_text(code, encoding="utf-8")
    subprocess.run(["cc", "-std=c11", "-fshort-wchar", "-O2", str(src), "-lcrypto", "-o", str(exe)], check=True)
    return exe


def check(exe, scenario, expected, rows):
    result = subprocess.run([str(exe), scenario], text=True, capture_output=True, timeout=5, check=True)
    observed = result.stdout.strip()
    rows.append({"binary": exe.name, "case": scenario, "expected": expected, "observed": observed})
    if observed != expected:
        raise AssertionError(f"{exe.name}/{scenario}: expected {expected}, got {observed}")


def run(source, output):
    lock = json.loads((profile.ROOT / "firmware-source.json").read_text())
    originals = {name: (source / name).read_text(encoding="utf-8") for name in lock["sources"]}
    # apply() verifies exact bytes before mutation; compile both actual versions.
    with tempfile.TemporaryDirectory(prefix="wcm-firmware-controls-") as tmp:
        directory = Path(tmp)
        rows = []
        strip_headers = lambda s: re.sub(r"^#include[^\n]*$", "", s, flags=re.M)
        original = compile_c(directory, "upstream-verifier", HEADER + strip_headers(originals[profile.VERIFIER]) + VERIFIER_MAIN)
        check(original, "kernel", "ALLOW", rows)
        check(original, "missing", "ALLOW", rows)  # pre-fix counterexample
        candidate = directory / "candidate"
        for name in originals:
            target = candidate / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / name).read_bytes())
        profile.apply(candidate)
        patched = {name: (candidate / name).read_text(encoding="utf-8") for name in originals}
        verifier = compile_c(directory, "restricted-verifier", HEADER + strip_headers(patched[profile.VERIFIER]) + VERIFIER_MAIN)
        for scenario in ("kernel", "initrd", "cmdline"):
            check(verifier, scenario, "ALLOW", rows)
        for scenario in ("missing", "duplicate", "order", "zero-length", "oversized-entry", "truncated",
                         "absent", "hash-failure", "unknown", "tamper", "fetch-failure"):
            check(verifier, scenario, "STOP", rows)
        routes = "".join(extract(patched[profile.LOADER], name, "static EFI_STATUS")
                         for name in ("QemuKernelFetchNamedBlobs", "QemuKernelRegisterIgvmBlobs"))
        routes += "".join(extract(patched[profile.MANAGER], name, "void") for name in
                          ("PlatformBootManagerBeforeConsole", "PlatformBootManagerAfterConsole", "PlatformBootManagerUnableToBoot"))
        route = compile_c(directory, "restricted-routes", HEADER + ROUTE_HEADER + routes + ROUTE_MAIN)
        for scenario in ("named-0", "named-1", "named-2", "too-many", "igvm-present"):
            check(route, scenario, "DENY", rows)
        for scenario in ("empty", "unrelated", "igvm-absent"):
            check(route, scenario, "ALLOW", rows)
        for scenario in ("kernel-error", "kernel-return"):
            check(route, scenario, "STOP:1:2:1:1", rows)
        check(route, "transfer", "TRANSFER:1:2:1:1", rows)
        for scenario in ("after", "unable"):
            check(route, scenario, "STOP:0:0:0:0", rows)
        # Deliberately weaken each route in the actual extracted C. The same
        # oracle must reject it, not merely recognize an altered source string.
        mutations = (
            ("named", 'CompareMem (Entry.FileName, "etc/boot/", 9) == 0', '0', "named-1", "DENY"),
            ("igvm", 'GetFirstGuidHob (&gEfiIgvmDataHobGuid) != NULL', '0', "igvm-present", "DENY"),
            ("fallback", '  CpuDeadLoop ();', '  return;', "kernel-return", "STOP:1:2:1:1"),
        )
        for name, old, new, scenario, expected in mutations:
            mutant = compile_c(directory, "weakened-" + name, HEADER + ROUTE_HEADER + routes.replace(old, new) + ROUTE_MAIN)
            try:
                check(mutant, scenario, expected, [])
            except AssertionError:
                rows.append({"mutation": name, "detected": True})
            else:
                raise AssertionError("mutation survived: " + name)
        output.write_text(json.dumps({"hardware_validated": False, "uefi_services_simulated": True,
                                      "observations": rows}, indent=2) + "\n")
        print(f"{len(rows)} native observations passed, including upstream counterexample and three mutations")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(args.source, args.output)
