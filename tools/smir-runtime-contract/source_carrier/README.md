# Experimental source carrier

A bounded structural reader/writer for section3 revision2/3 and complete ten-root
SMOs. APIs require the existing canonical SourceQueryBudget. Decoded records remain
unbound with executable=false, semantic_admission=false, active_v3_verified=false.
Existing CandidateCodec still rejects revision3. No source/runtime facts are issued.

The exact schema is schema/runtime/source_carrier_records.json (c64512...). Optional
original-v2 comparison retains only that independently supplied actual owner/stamp;
it cannot issue an original-v3 stamp. All observer semantic paths remain unavailable;
full-module observer result type must be actual SELF Journal (external kind unavailable).

Generate/check only owned products with `python3 -B -m source_carrier.schema --check`
and `python3 -B -m source_carrier.fixtures --check` from an environment whose
PYTHONPATH includes tools/smir-runtime-contract. Build the actual independent oracle
with `python3 -B -m source_carrier.oracle --output <fresh-external-dir>
--compiler <absolute-C++-compiler> [--sysroot <SDK>]`. Set
SMIR_SOURCE_CARRIER_ORACLE to its resulting probe and SMIR_SOURCE_CARRIER_TMPDIR to
an external scratch directory before discovering test_source_carrier.py. The
launcher runs real same-mode child tests and preserves the parent's codec/sys.path.
The oracle establishes ordered grammar/reencoding only, without reference/digest/
semantic or execution admission. SDK/shared-library/file-open attestation is outside
its source/compiler before-after guards. Full platform/compiler freeze remains open.
