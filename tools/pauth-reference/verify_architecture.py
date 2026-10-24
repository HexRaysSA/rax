#!/usr/bin/env python3
"""Compare PAC placement, stripping, and all accepted failure profiles with QEMU.

The pinned QEMU functions remain byte-for-byte unchanged. Fixture shims supply
already-resolved VA parameters and feature selection; this does not test MMU or
privilege-control resolution. Both results and complete fault ISS are compared.
"""

import argparse
import hashlib
import itertools
import os
from pathlib import Path
import random
import tempfile

from verify import REFERENCE, REFERENCE_SHA256, ROOT, run

HEADER = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdlib.h>
#define MAKE_64BIT_MASK(s,n) (((UINT64_C(1) << (n))-1) << (s))
static uint64_t extract64(uint64_t x,int s,int n) {
    return (x>>s)&((UINT64_C(1)<<n)-1);
}
static int64_t sextract64(uint64_t x,int s,int n) {
    return ((int64_t)(x << (64-s-n))) >> (64-n);
}
static uint64_t deposit64(uint64_t x,int s,int n,uint64_t y) {
    uint64_t mask = MAKE_64BIT_MASK(s,n);
    return (x & ~mask) | ((y << s) & mask);
}
#define extract32 extract64
typedef struct { uint64_t lo, hi; } ARMPACKey;
typedef enum { PauthFeat_Base, PauthFeat_EPAC, PauthFeat_2,
               PauthFeat_FPAC, PauthFeat_FPACCOMBINED } ARMPauthFeature;
typedef struct { bool tbi; int tsz; } ARMVAParameters;
typedef struct { bool q3; ARMPauthFeature pauth_feature; ARMVAParameters va; } CPUARMState;
typedef CPUARMState ARMCPU;
typedef int ARMMMUIdx;
#define env_archcpu(env) (env)
#define cpu_isar_feature(name,cpu) ((cpu)->name)
static ARMMMUIdx arm_stage1_mmu_idx(CPUARMState *env) { return 0; }
static ARMVAParameters aa64_va_parameters(CPUARMState *env, uint64_t ptr,
                                         int index, bool data, bool s1) {
    return env->va;
}
static uint64_t pauth_ptr_mask(ARMVAParameters param) {
    return MAKE_64BIT_MASK(64-param.tsz, param.tsz - 8*param.tbi);
}
static jmp_buf failure;
static unsigned fault_iss;
#define G_NORETURN __attribute__((noreturn))
#define EXCP_UDEF 1
static unsigned syn_pacfail(bool data,int keynumber) { return (data << 1) | keynumber; }
static int exception_target_el(CPUARMState *env) { return 1; }
static G_NORETURN void raise_exception_ra(CPUARMState *env,int excp,unsigned iss,
                                         int target,uintptr_t ra) {
    fault_iss = iss;
    longjmp(failure, 1);
}
'''

COMPUTE = r'''
static uint64_t pauth_computepac(CPUARMState *env,uint64_t data,uint64_t modifier,ARMPACKey key) {
    return pauth_computepac_architected(data,modifier,key,env->q3);
}
'''

DRIVER = r'''
int main(void) {
    unsigned q, profile, bits, tbi, data, key_b, combined, operation;
    uint64_t pointer, modifier, lo, hi, corruption;
    const ARMPauthFeature profiles[] = {PauthFeat_Base, PauthFeat_2, PauthFeat_FPAC, PauthFeat_FPACCOMBINED};
    while (scanf("%u %u %u %u %u %u %u %u %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64,
                 &q,&profile,&bits,&tbi,&data,&key_b,&combined,&operation,
                 &pointer,&modifier,&lo,&hi,&corruption) == 13) {
        CPUARMState env = {q != 0, profiles[profile], {tbi != 0,64-bits}};
        ARMPACKey key = {lo,hi};
        if (setjmp(failure)) {
            printf("fault %x\n", fault_iss);
            continue;
        }
        uint64_t result;
        if (operation == 0) {
            result = pauth_addpac(&env,pointer,modifier,&key,data);
        } else if (operation == 2) {
            result = pauth_strip(&env,pointer,data);
        } else {
            if (operation >= 3) {
                pointer = pauth_addpac(&env,pointer,modifier,&key,data);
                if (operation == 4) { pointer ^= corruption; }
            }
            result = pauth_auth(&env,pointer,modifier,&key,data,key_b,0,combined);
        }
        printf("ok %016" PRIx64 "\n",result);
    }
}
'''

RUST = r'''
use std::io::{self,BufRead};
use pauth::{PauthAddressLayout,PauthAlgorithm,PauthProfile,PauthKey,PauthFailure};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        let selector: Vec<u32> = fields[..8].iter().map(|v| v.parse().unwrap()).collect();
        let values: Vec<u64> = fields[8..].iter().map(|v| u64::from_str_radix(v,16).unwrap()).collect();
        let algorithm = if selector[0] == 0 { PauthAlgorithm::Qarma5 } else { PauthAlgorithm::Qarma3 };
        let profile = [PauthProfile::Base,PauthProfile::Pauth2,PauthProfile::Fpac,PauthProfile::FpacCombine][selector[1] as usize];
        let layout = PauthAddressLayout::new(selector[2] as u8,selector[3] != 0).unwrap();
        let key = PauthKey {lo:values[2],hi:values[3]};
        let mut pointer = values[0];
        let modifier = values[1];
        let operation = selector[7];
        let failure = PauthFailure {data:selector[4] != 0,key_b:selector[5] != 0};
        let result = if operation == 0 {
            Ok(layout.sign(algorithm,profile,pointer,modifier,key))
        } else if operation == 2 {
            Ok(layout.strip(pointer))
        } else {
            if operation >= 3 {
                pointer = layout.sign(algorithm,profile,pointer,modifier,key);
                if operation == 4 { pointer ^= values[4]; }
            }
            layout.authenticate(algorithm,profile,pointer,modifier,key,failure,selector[6] != 0)
        };
        match result {
            Ok(value) => println!("ok {value:016x}"),
            Err(fault) => println!("fault {:x}",(u32::from(fault.data)<<1)|u32::from(fault.key_b)),
        }
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=4096, help="additional random cases")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0xA64_20261024)
    args = parser.parse_args()
    if args.cases < 0:
        parser.error("--cases must be nonnegative; exhaustive structured cases always run")
    if hashlib.sha256(REFERENCE.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise SystemExit("reference hash mismatch")
    source = REFERENCE.read_text()
    primitive = source[source.index("static uint64_t pac_cell_shuffle"):source.index("static uint64_t pauth_computepac_impdef")]
    architecture = source[source.index("static uint64_t pauth_addpac"):source.index("static G_NORETURN\nvoid pauth_trap")]
    rng = random.Random(args.seed)
    selectors = list(itertools.product(range(2),range(4),range(16,49),range(2),range(2),range(2),range(2),range(5)))
    selectors.extend(tuple([rng.randrange(2),rng.randrange(4),rng.randrange(16,49)] + [rng.randrange(2) for _ in range(4)] + [rng.randrange(5)]) for _ in range(args.cases))
    lines = []
    for q,profile,bits,tbi,data,key_b,combined,operation in selectors:
        # Alternate arbitrary, canonical lower, and canonical upper pointers.
        pointer = rng.getrandbits(64)
        kind = rng.randrange(3)
        if kind == 1:
            pointer &= (1 << bits) - 1
        elif kind == 2:
            pointer |= ((1 << 64) - 1) ^ ((1 << bits) - 1)
        # Corrupt a random PAC bit without relying on the candidate's mask.
        positions = [bit for bit in range(bits,56 if tbi else 64) if bit != 55]
        corruption = 1 << rng.choice(positions)
        values = [pointer,rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64),corruption]
        lines.append(" ".join(map(str,[q,profile,bits,tbi,data,key_b,combined,operation])) + " " + " ".join(f"{value:016x}" for value in values))
    inputs = "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory(prefix="rax-pauth-arch-") as temporary:
        directory = Path(temporary)
        c_path = directory / "reference.c"
        rust_path = directory / "rax.rs"
        c_path.write_text(HEADER + primitive + COMPUTE + architecture + DRIVER)
        rust_path.write_text(f'#[path = "{(ROOT / "src/isa/arm/aarch64/pauth.rs").as_posix()}"] mod pauth;\n' + RUST)
        reference = directory / "reference"
        candidate = directory / "rax"
        run([os.environ.get("CC","cc"),"-O2",str(c_path),"-o",str(reference)])
        run(["rustc","+stable","--edition","2024","-O",str(rust_path),"-o",str(candidate)])
        expected = run([str(reference)],input=inputs).stdout.splitlines()
        actual = run([str(candidate)],input=inputs).stdout.splitlines()
    if len(expected) != len(lines) or len(actual) != len(lines):
        raise SystemExit(f"case count mismatch: inputs={len(lines)} expected={len(expected)} actual={len(actual)}")
    for index,(left,right) in enumerate(zip(expected,actual)):
        if left != right:
            raise SystemExit(f"mismatch at {index}: input={lines[index]} QEMU={left} RAX={right}")
    faults = sum(line.startswith("fault ") for line in expected)
    if not faults:
        raise SystemExit("oracle did not exercise an authentication failure")
    print(f"PASS: {len(lines)} cases, {faults} exact faults, seed={args.seed:#x}, no skips")
    print("coverage: QARMA3/QARMA5; Base/PAuth2/FPAC/FPACCOMBINE; 16..48 address bits; TBI on/off; IA/IB/DA/DB; standalone/combined")
    print(f"reference_sha256={REFERENCE_SHA256}")


if __name__ == "__main__":
    main()
