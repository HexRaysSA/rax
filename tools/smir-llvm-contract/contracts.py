"""CC-L exact lowering recipe registry; reference plans only, no emitter.

Names below are symbolic cross-role interface requirements, not allocated public
opcodes. Execution/helper binding is checked separately against accepted schemas.
"""


def recipe(targets, operands, results, steps, poison, effects, helpers=()):
    return dict(targets=targets.split(), operands=operands, results=results,
                steps=steps, poison=poison, effects=effects, helpers=list(helpers),
                state='specified_local_draft', emitter_implemented=False)


RECIPES = {
    'return': recipe('return', 'ordered declared result values', 'none',
        ['Validate logical signature and result count/types.',
         'Apply ABI source-result conversion and noundef checks.',
         'Complete required normal-exit journal actions before publishing continuation.'],
        'noundef violation is executed language UB; otherwise preserve poison components.',
        'Result publication exactly once after normal cleanup.'),
    'branch': recipe('jump cbranch switch', 'condition i1 or switch iN; explicit successors', 'none',
        ['Unconditional branch transfers to target.',
         'Conditional branch consumes concrete i1; poison/undef condition is immediate UB.',
         'Switch compares exact iN bits to distinct sorted case bitpatterns then default.',
         'Commit predecessor and simultaneous phi snapshot on chosen edge.'],
        'Only executed condition consumed. Dead successors have no effects.', 'Control-flow frontier only.'),
    'integer': recipe('integer', 'same-width scalar/fixed-vector integers and exact LLVM flags', 'same type',
        ['Per lane evaluate mathematical operation modulo2^w.',
         'For nsw/nuw require signed/unsigned mathematical result representable, else poison.',
         'Overshift count>=w poisons; exact right shift requires discarded bits zero.',
         'or disjoint requires no shared set bit; otherwise poison.'],
        'Lane-local poison; no eager trap from unconsumed result.', 'Pure.'),
    'division': recipe('integer', 'same-width integer dividend/divisor; exact on division only', 'same type',
        ['On executed instruction, zero/poison divisor is immediate UB.',
         'Signed MIN/-1 or poison/-1 is immediate UB for quotient AND remainder.',
         'Signed quotient truncates toward zero; remainder=a-q*b.',
         'exact division with remainder poisons; vector any exceptional divisor is immediate UB.'],
        'Other poison dividend produces poison.', 'Language UB at current operation only.'),
    'fp': recipe('fp_binary fp_unary fp_compare fp_convert',
        'typed raw FP bits / integer bits; format; opcode; mode; rounding; exception behavior; copyable fenv snapshot',
        'typed raw FP or integer bits; sticky status when constrained',
        ['fneg toggles sign bit and preserves NaN payload/signaling status.',
         'Ordinary arithmetic uses default nearest-even, subnormals preserved; no guest fenv flags.',
         'Constrained operations use explicit/dynamic rounding and ignore/maytrap/strict behavior.',
         'frem is x-trunc(x/y)*y with exact intermediate mathematical remainder then result rounding; not IEEE remainder.',
         'sqrt rounds exact nonnegative root; negative finite nonzero generates invalid NaN.',
         'fcmp uses explicit16 ordered/unordered predicates; fcmp quiet, fcmps signals invalid for any NaN.',
         'fptosi/ui truncate toward zero; nonrepresentable ordinary conversion produces poison.',
         'sitofp/uitofp/fptrunc round once to destination; fpext exact except specified NaN treatment.',
         'Apply nnan/ninf/nofpclass promises as poison where required; choose no reassociation/fusion unless fma.',
         'Vector operations compose per-lane values; constrained lane flags union before trap/result commit.'],
        'Input poison lane propagates. Ordinary invalid fptoint is poison, not immediate trap.',
        'Constrained flags update before enabled diagnostic FP trap; no result commit on trap.',
        ('fp.evaluate', 'fenv.access')),
    'memory': recipe('alloca load store lifetime stack_save stack_restore',
        'storage type, section1 execution memory layout, optional section10 nominal+storage binding, guest pointer, size/align, volatile, lifetime token and optional bytes+shadow',
        'loaded typed value or fresh allocation pointer/token',
        ['Compute allocation/access geometry from admitted section1 execution memory layout; source-visible storage also verifies section10 alias-faithful storage binding. Alloca count multiply/add is checked.',
         'Alloca allocates activation-owned guest storage with max(requested,execution layout) alignment.',
         'Validate guest lifetime, permission, alignment and whole access bounds under shared backing guard.',
         'Load/store bytes and poison/provenance shadow together; volatile preserves access count/order.',
         'Non-byte integer writes zero unused high bits inside ceil(width/8) access bytes only; allocation-tail padding untouched. Nonzero or poison discarded high load bits produce scalar poison.',
         'Layout size/alignment/access_bytes are bytes; field offsets/width and sequence stride are bits. Packed vector<i1> stride1 differs from array<i1> stride8; elementwise atomics require byte-multiple scalar lanes and resume at next unfinished lane.',
         'lifetime.start marks interval live and uninitialized; lifetime.end revokes interval; stackrestore invalidates allocations after mark.'],
        'Poison address is language UB; stored poison is shadow, not silently zeroed.',
        'Fault before whole access mutation; completed access advances exact operation frontier.',
        ('memory.access', 'stack.allocate', 'stack.mark', 'stack.restore', 'lifetime.change')),
    'gep': recipe('pointer_offset', 'base data pointer; source storage type/layout; signed indices; inbounds/nusw/nuw flags',
        'data pointer preserving allocation identity/generation',
        ['Sign-extend or truncate sequential indices to64-bit pointer index width.',
         'First sequential index scales source allocation stride; struct fields use constant ABI offsets.',
         'Compose offset in mathematical integers then low64 address bits for unflagged arithmetic.',
         'nusw: trunc preserves signed value, multiply and accumulated offsets fit signed64, unsigned base plus each signed offset stays0..2^64-1. nuw: trunc preserves unsigned value, multiply/accumulated offsets and each unsigned base+offset fit unsigned64. Each failed promise poisons.',
         'inbounds implies nusw; base and every successive address stay within original allocation including one-past; allocation may be deallocated; all-zero indices are always inbounds. Violations poison; dereference lifetime is checked separately.',
         'S075 ptr_offset check_base=true preserves nonzero ORIGINAL index base obligation even for zero byte displacement; true requires inbounds. Select original base only when ALL original indices are zero. Tombstone allocation bounds remain valid; GEP alone never dereferences.',
         'Symbolic constant indices use checked cast roundtrip/icmp/select, flagged multiply and accumulated add before pointer steps; literal-index prefix may be discharged by normalize_indices.'],
        'Poison base/index propagates; invalid inbounds result deferred poison.',
        'No memory access; inrange constant-GEP carries half-open access interval and closed-range comparison constraints; violating derived accesses/comparisons/exposures is source UB. Provenance alone grants no permissions.'),
    'atomic': recipe('atomic_access fence',
        'storage/layout; pointer; width; operation; expected/desired or operand; success/failure order; scope; weak; volatile',
        'observed typed bytes+shadow and CAS success bool, or no result',
        ['Validate pinned LLVM IR atomic type, width, alignment and ordering constraints.',
         'Bind generic arbitrary-positive-byte lock-backed helper using accepted ABI atomic storage/padding mask.',
         'Preserve byte/shadow observation and compare+update under one shared-backing linearization guard.',
         'CAS weak may use strong behavior; failure never stores; success returns prior observed value and true.',
         'RMW xchg/add/sub/and/nand/or/xor/smin/smax/umin/umax/uinc_wrap/udec_wrap/usub_cond/usub_sat/FP forms use exact pinned operator on observed value.',
         'LLVM fence accepts acquire/release/acq_rel/seq_cst only; source dynamic atomic_fence order0 relaxed is a no-op with no SC event, consume order1 refines acquire. Other memory orders may strengthen to SC, singlethread only constrains current guest thread; process/system map guest process.',
         'Always report baseline lock-free false; no host atomic or pointer substitution.'],
        'Poison address/immediate UB rejected at executed sink; shadow transfers atomically.',
        'One linearization/commit ticket; cancellation cannot replay completed operation.', ('atomic.access',)),
    'integer-cast': recipe('trunc zext sext', 'source integer; exact flags; destination width', 'destination integer',
        ['trunc keeps low destination bits; zext fills zero; sext replicates source sign.',
         'trunc nuw requires dropped high bits zero; trunc nsw requires sign-extension roundtrip.',
         'zext nneg requires source sign bit zero; otherwise poison.'],
        'Input/promise poison propagates.', 'Pure.'),
    'pointer': recipe('raw_bitcast pointer_expose pointer_recover pointer_offset',
        'typed integer/raw/pointer operand; result type; actual validated semantic domain; data AS0 or allocated program AS1', 'destination typed value',
        ['Raw bN stores per-bit poison and pointer-origin bit identities; slicing/concatenation preserve shadows.',
         'Bitcast changes view at equal bit width; scalar integer/FP any poisoned bit poisons scalar.',
         'Bitcast to pointer restores provenance only from all64 correctly ordered origin bits of one admitted pointer.',
         'DataPtr AS0 ptrtoint captures address AND exposes allocation provenance in process exposure registry; zero/sign conversion per destination width.',
         'ptrtoaddr returns low64 index bits without exposure; destination must i64.',
         'DataPtr AS0 inttoptr recovers only live exposed matching allocation identity under registry policy; otherwise non-dereferenceable address.',
         'For validated source CodeAddress in AS1, generic LLVM ptrtoint/inttoptr are pure bits/from_bits and neither expose nor recover authority. Source observing exposure/recovery uses exact LLVM018 helpers before optimization; B typed binding keeps its independent actual Fn/permit.',
         'Identity address-space casts preserve only an already validated semantic kind. AS0/AS1 conversion requires its separately admitted exact contract; other address spaces diagnose. AS1 alone never selects source CodeAddress or callability; BlockAddress keeps its existing computed-label diagnostic.',
         'Frozen poison pointer remains non-dereferenceable; arbitrary numeric code values confer no call authority.'],
        'Preserve per-component and per-bit shadow; never globally zero pointer provenance.',
        'Exposure registry updates are logical guest state; no host addresses serialized.', ('pointer.expose', 'pointer.recover')),
    'compare': recipe('icmp', 'same-width integers/pointers; predicate; samesign flag', 'i1 or vector i1',
        ['Evaluate eq/ne/ugt/uge/ult/ule/sgt/sge/slt/sle on raw/signed mathematical bits.',
         'samesign requires matching sign bits; else poison.',
         'Pointer equality compares guest representations; existing data/typed-pointer ordering uses guest unsigned address, no host comparison. Source CodeAddress permits only eq/ne, never ordering; AS1 alone cannot select that semantic kind.'],
        'Lane-local operand/promise poison.', 'Pure.'),
    'phi': recipe('phi', 'exact predecessor->value mapping', 'typed value',
        ['Read all incoming selected values from predecessor snapshot.',
         'Commit all outputs simultaneously, including loops and cycles.',
         'Invoke result uses split virtual normal/unwind edge definition and edge dominance.'],
        'Only predecessor-selected value shadow propagates.', 'Block-entry frontier.'),
    'call': recipe('call tailcall', 'target direct/indirect/import; normalized signature; ABI call descriptor; args; bundles', 'ordered logical results',
        ['Resolve abi_signature in section10 call_signature, whose function_type resolves source nominal type; never infer table from an equal numeric ID.',
         'Apply portable ABI recipe: direct scalars/complex/vectors; fresh record copies; hidden sret first; this/VTT order.',
         'Validate target live code/import token, signature, module generation and leases.',
         'Check stable source ABI noundef/cc independently from extra optimization promises; instantiate typed vararg arena after promotions with exact arena+u64bytes noundef suffix and execution variadic=false.',
         'Publish suspended caller activation and original unwind continuation before reentrant or blocking target.',
         'Foreign RETURNED is private target storage; conversion/journal cleanup precede portable normal result commit.',
         'musttail requires exact lowered signature/result/lifetime compatibility and no pending journal action, otherwise compile error.',
         'tail hint may become ordinary call; musttail replacement releases caller activation only after required actions.'],
        'Poison callee/noundef inputs are language UB; target return constraints checked before commit.',
        'Call entry once; normal results once; thrown conversion targets original invoke edge.', ('call.dispatch', 'varargs.pack')),
    'select': recipe('select', 'i1 or vector condition; same-type arms', 'same type',
        ['Scalar condition chooses whole arm; vector condition chooses lane.',
         'Only selected value shadow contributes; no branch on unselected poison.',
         'Pointer/aggregate components preserved without new authority.'],
        'Poison condition poisons selected result components.', 'Pure.'),
    'freeze': recipe('freeze', 'typed arbitrary value including aggregate/raw/pointer', 'same type',
        ['Freeze once per dynamic instruction, reuse one result for all uses.',
         'Each poison/undef scalar or lane/field chooses concrete zero; concrete components preserved.',
         'Raw bN freezes poison per bit, retaining concrete pointer-origin bits.',
         'Pointer freeze from poison/undef yields non-dereferenceable zero address.'],
        'No poison result; no new provenance.', 'Pure.'),
    'aggregate': recipe('extract insert shuffle', 'typed aggregate/vector; indices/mask', 'typed components or updated composite',
        ['extractvalue/insertvalue use constant valid structural index paths; malformed paths compile error.',
         'extractelement/insertlement out-of-range dynamic lane poisons extracted/whole result as LangRef requires.',
         'shuffle chooses lanes from concatenated operands with exact fixed mask; poison mask lanes remain poison.',
         'Field/lane poison never contaminates unrelated components.'],
        'Per-field/per-lane; no whole-composite collapse.', 'Pure.'),
    'varargs': recipe('va_arg', 'va_list handle/storage, promoted nominal type and layout', 'typed promoted value',
        ['Validate owning thread/activation cookie before storage bounds.',
         'Read exact typed arena header32 B; verify promoted type, size/alignment and canonical next.',
         'Load payload bytes/shadow, then advance cursor once; failure leaves cursor unchanged.',
         'va_copy duplicates cursor into independent list; va_end zeros/invalidates list.'],
        'Payload retains poison/provenance; invalid type/lifetime precise helper trap.',
        'Cursor commit after successful read.', ('varargs.access',)),
    'logical-eh': recipe('invoke eh_landing resume', 'typed target, normal/unwind edge results, region/action/ABI descriptors', 'normal results OR exception lease',
        ['Split dedicated normal and unwind edge blocks and validate virtual-edge dominance.',
         'Invoke publishes no result until portable call including conversion/cleanup completes.',
         'landingpad maps admitted exception lease+source selector; catch/filter metadata uses nominal ABI identities.',
         'Global search is read-only; select typed/catch-all handler with base adjustment/catch-copy recipe.',
         'Action program names ABI cleanup_program, recipe names adapter_recipe; captures form exact formal-ID/type bijection and dominate PRE-trigger. Same invoke normal result cannot be captured on its unwind edge.',
         'cleanup_program.signature identifies source owner; independent program.params declares journal captures, distinct from action recipe params. count_source resolves unsigned nominalu64 noundef captured formal.',
         'journal operation program names cleanup_program, operands exactly livejournal/slot:u32/element:u64 and zero results; selected helper is journal_advance with abiSome(program) and action exactly one of its seven contract tokens, never adapter_recipe or an inferred default instance.',
         'Class arrays instantiate a child cleanup program per element with exact parent instance/slot/element; preserve partial child and prior parent-element progress independently.',
         'Complete construction publishes authoritative process-owned lifetime certificate; ordinary destructor/delete claims fresh current-thread journal seeded from certificate revision/activechildren/counts, never retags constructor events or requires user transfer API. Duplicate/stale claim rejects before destructor entry.',
         'Preserve arbitrary cleanup CFG as an admitted cleanup function invoked by recipe with captures, never a destructor-pattern guess.',
         'Execute typed construction/cleanup journal exactly once in phase2, not again in landingpad CFG; resume/rethrow preserve exception identity. Suspension retains action cursor/captures/journal/leases; cleanup throw during active unwind terminates.',
         'Source throw; uses eh_rethrow_current with no hidden E argument, querying logical active-catch stack; absent catch invokes source terminate. Explicit low-level eh_rethrow(E) and saved unwind resume remain distinct.',
         'Bare rethrow inherits caught handler snapshot; retained-owner rethrow captures current global. Source terminate selects top active caught snapshot else global, establishing causing implicit catch for unhandled/noexcept/catch-copy cases; handler return/throw aborts without redispatch.',
         'Noexcept termination and forced unwind/nonlocal escape use explicit descriptor policy, never Rust/host unwind.'],
        'Exceptional results never available on normal edge and conversely.',
        'Two-phase search/cleanup; exact original throw/invoke frontier and leases.', ('eh.dispatch', 'journal.advance')),
    'ub': recipe('unreachable', 'none', 'none', ['On execution report language_ub at exact logical operation.'],
        'No value result.', 'Prior completed effects retained; no source-defined post-UB behavior.'),
}

# Optional source extensions: exact diagnostic classification, no missing-contract
# placeholder for a required C23/C++23 family.
OPTIONAL_RULES = {
    'reject-block-address': 'E-EXT-COMPUTED-LABEL: GNU computed goto/callbr/native asm labels are outside hosted ISO C/C++ baseline.',
    'reject-funclet': 'E-EXT-NATIVE-EH: Microsoft/SEH native funclet IR must enter through admitted foreign descriptor; portable frontend uses logical Itanium EH.',
    'reject-internal': 'E-INTERNAL-OPCODE: pass-only UserOp1/2 cannot cross LLVM module verifier boundary.',
}

MATH = set('acos asin atan atan2 ceil cos cosh exp exp10 exp2 fabs floor fma fmuladd frexp ldexp llrint llround log log10 log2 lrint lround maximum maximumnum maxnum minimum minimumnum minnum modf nearbyint pow powi rint round roundeven sin sincos sincospi sinh sqrt tan tanh trunc canonicalize copysign is_fpclass fptosi_sat fptoui_sat fptrunc_round'.split())


def intrinsic_contract(name, target_prefix):
    if target_prefix:
        return 'diagnostic', 'E-TARGET-INTRINSIC', 'extension.target_isa'
    stem = name.removeprefix('int_')
    if stem == 'debugtrap':
        return 'diagnostic', 'E-EXT-DEBUGGER', 'extension.resumable_debugger'
    if stem == 'protected_field_ptr':
        return 'diagnostic', 'E-EXT-PROTECTED-FIELD', 'extension.encoded_pointer_storage'
    if stem in {'load_relative','type_checked_load_relative'}:
        return 'diagnostic', 'E-EXT-RELATIVE-POINTERS', 'extension.relative_pointer_profile'
    if stem.startswith('experimental_constrained_') or stem in MATH:
        return 'helper', '', 'fp.math'
    if stem.startswith(('coro_async_', 'coro_prepare_async', 'coro_prepare_retcon')) or stem in {
            'coro_id_async', 'coro_id_retcon', 'coro_id_retcon_once', 'coro_suspend_retcon', 'coro_begin_custom_abi', 'coro_end_async'}:
        return 'diagnostic', 'E-EXT-COROUTINE-ABI', 'extension.custom_coroutine'
    if stem.startswith('coro_'):
        return 'expansion', '', 'coroutine.presplit'
    if stem.startswith(('memcpy', 'memmove', 'memset', 'experimental_memset_pattern')):
        return 'helper', '', 'memory.intrinsic'
    if stem.startswith(('masked_', 'vp_', 'vector_', 'experimental_vector_', 'experimental_vp_')) or stem in {
            'stepvector', 'get_active_lane_mask', 'experimental_cttz_elts'}:
        return 'expansion', '', 'vector.fixed'
    if stem in {'vscale', 'experimental_get_vector_length'}:
        return 'diagnostic', 'E-EXT-SCALABLE-VECTOR', 'extension.scalable'
    if stem.startswith(('dbg_', 'annotation', 'ptr_annotation', 'var_annotation', 'codeview_annotation')):
        return 'expansion', '', 'metadata.debug'
    if stem.startswith(('objc_', 'ptrauth_', 'hwasan_', 'asan_', 'experimental_gc_', 'experimental_convergence_', 'experimental_patchpoint', 'instrprof_', 'preserve_')):
        return 'diagnostic', 'E-EXT-INSTRUMENTATION-OR-LANGUAGE', 'extension.nonbaseline'
    groups = {
        'raw.integer_intrinsic': '''abs bitreverse bswap ctlz ctpop cttz fshl fshr sadd_sat uadd_sat ssub_sat usub_sat sadd_with_overflow uadd_with_overflow ssub_with_overflow usub_with_overflow smul_with_overflow umul_with_overflow smin smax umin umax smulh umulh scmp ucmp sshl_sat ushl_sat clmul pdep pext''',
        'pointer.intrinsic': 'ptrmask strip_invariant_group launder_invariant_group ssa_copy structured_gep',
        'stack.intrinsic': 'stacksave stackrestore structured_alloca call_preallocated_arg call_preallocated_setup call_preallocated_teardown',
        'lifetime.intrinsic': 'lifetime_start lifetime_end invariant_start invariant_end',
        'tls.intrinsic': 'threadlocal_address',
        'fenv.intrinsic': 'get_fpenv set_fpenv reset_fpenv get_fpmode set_fpmode reset_fpmode get_rounding set_rounding',
        'varargs.intrinsic': 'vastart vacopy vaend',
        'eh.intrinsic': 'eh_typeid_for eh_unwind_init',
        'typecheck.intrinsic': 'type_test public_type_test type_checked_load',
        'assumption.intrinsic': 'assume expect expect_with_probability experimental_noalias_scope_decl arithmetic_fence',
        'no_effect.intrinsic': 'donothing fake_use prefetch reloc_none pcmarker pseudoprobe is_constant allow_runtime_check allow_ubsan_check allow_sanitize_address allow_sanitize_hwaddress allow_sanitize_memory allow_sanitize_thread',
        'trap.intrinsic': 'trap ubsantrap looptrap',
        'effect.intrinsic': 'sideeffect',
        'objectsize.intrinsic': 'objectsize',
        'counter.intrinsic': 'readcyclecounter readsteadycounter',
    }
    for group, members in groups.items():
        if stem in members.split():
            return ('helper' if group in ('tls.intrinsic', 'fenv.intrinsic', 'varargs.intrinsic', 'eh.intrinsic', 'stack.intrinsic') else 'expansion'), '', group
    optional = (
        'eh_sjlj_', 'eh_dwarf_', 'eh_exception', 'eh_recover', 'eh_return_', 'seh_', 'swift_', 'gc', 'experimental_deoptimize', 'experimental_guard',
        'experimental_stackmap', 'sdiv_fix', 'udiv_fix', 'smul_fix', 'umul_fix', 'matrix_',
        'loop_', 'set_loop_', 'start_loop_', 'test_set_loop_', 'test_start_loop_',
        'read_register', 'read_volatile_register', 'write_register', 'write_volatile_register',
        'xray_', 'init_trampoline', 'adjust_trampoline', 'convert_from_arbitrary_fp', 'convert_to_arbitrary_fp',
    )
    if stem.startswith(optional) or stem in {
            'addressofreturnaddress', 'frameaddress', 'returnaddress', 'localaddress', 'localescape',
            'localrecover', 'thread_pointer', 'stackaddress', 'stackguard', 'stackprotector',
            'get_dynamic_area_offset', 'callbr_landingpad', 'clear_cache', 'icall_branch_funnel',
            'sponentry', 'alloc_token_id', 'experimental_widenable_condition', 'cond_loop'}:
        return 'diagnostic', 'E-EXT-NONBASELINE', 'extension.nonbaseline'
    return 'diagnostic', 'E-UNCLASSIFIED-INTRINSIC', 'unclassified'


def attribute_contract(name):
    native = {'naked', 'nest', 'swiftasync', 'swifterror', 'swiftself',
              'fn_ret_thunk_extern', 'hybrid_patchable', 'jumptable',
              'marked_for_windows_hot_patching', 'allow_direct_access_in_hot_patch_function',
              'null_pointer_is_valid', 'vscale_range'}
    optional_instrumentation = {'safestack', 'shadowcallstack', 'speculative_load_hardening'}
    if name in native or name.startswith('sanitize_') or name in optional_instrumentation:
        return 'diagnostic', 'E-EXT-ATTRIBUTE', 'Explicit optional native/language/instrumentation profile; not a missing hosted-baseline contract.'
    if name in {'byval', 'byref', 'sret', 'signext', 'zeroext', 'noext', 'align', 'alignstack', 'elementtype', 'immarg', 'inalloca', 'preallocated', 'inreg'}:
        return 'expansion', '', 'call ABI recipe: validate pointee/storage/type/attribute location; apply explicit guest copy/sret/extension/alignment; inalloca/preallocated use one-use activation stack ticket, never physical register classification.'
    if name == 'returns_twice':
        return 'helper', '', 'nonlocal checkpoint: capture logical continuation, live values, stack mark and cleanup lease; second return restores logical control exactly once, without resetting the ambient guest FP environment merely because native FP registers were saved with source nonvolatile-modification UB rules.'
    if name in {'strictfp', 'denormal_fpenv', 'nofpclass', 'less-precise-fpmad', 'no-signed-zeros-fp-math'}:
        return 'expansion', '', 'FP recipe: preserve constrained environment; nofpclass exclusion produces poison, optional contraction/zero-sign freedoms need not be used; IEEE denormal baseline fixed, alternative requested mode needs explicit optional profile.'
    if name in {'convergent', 'noduplicate', 'nomerge'}:
        return 'expansion', '', 'Retain effect constraints through all portable optimization/scheduling: no duplication/merging and convergence control-equivalence preserved; no host SIMD inference.'
    if name in {'noundef', 'noreturn', 'nounwind'}:
        return 'expansion', '', 'Check executed source promise at logical boundary; poison/undef noundef is language UB, unexpected return/unwind is language UB; ordinary unused poison does not trap.'
    if name.startswith('coro_') or name == 'presplitcoroutine':
        return 'expansion', '', 'Run pinned ordinary C++ coroutine split/cleanup pipeline; materialize typed frame/lifetime/journal; validate no presplit intrinsic remains before wire lowering.'
    return 'expansion', '', 'Preserve exact typed LLVM optimization promise until final LLVM optimization; erase only facts with no remaining ABI/effect requirement. Portable optimizer cannot reuse an erased assumption. Validate original attribute placement/arguments with pinned LLVM verifier.'


INTRINSIC_DETAILS = {
    'fp.math': dict(target='fp.evaluate',
        semantics='Instantiate exact LLVM intrinsic opcode/format/rounding/exception metadata. Ordinary default environment; constrained flags committed before trap. LLVM minnum/maxnum ignore a sole quiet NaN but quiet signaling NaN/raise invalid per exact opcode; minimum/maximum propagate NaN and distinguish signed zero. Saturating fptoint clamps infinities/out-of-range, NaN->0. fmuladd chooses fused fma. Transcendentals use the selected correctly-rounded portable libm profile and exact C errno/domain policy where called through C library; LLVM intrinsic has no errno effect.',
        required_fields='opcode formats args mode rounding exceptions fenv',
        bindings=['fp', 'fenv.access']),
    'memory.intrinsic': dict(target='memory.copy_fill',
        semantics='Byte+poison+origin transfer. memcpy permits identical source/destination OR nonoverlapping ranges, rejects other partial overlap before writing; memmove snapshots whole source, memset clears old origins and writes repeated raw8 byte preserving poison/undef masks. Check original count well-defined before observing pointers/byte; zero length observes no pointer/value/memory/volatile effect modulo independently enforced argument attributes. memset.pattern repeats typed value count times at allocation stride, each ordinary store uses exact endian/padding/shadow semantics; count is NOT byte length. Undef/poison count is immediate UB; nonzero count requires well-defined dest and copy/move source; memset byte itself may carry poison/undef. Expand deterministic ascending stores preserving volatile access order/completed frontier, never byte-splat the pattern. Inline variant emits bounded operation expansion without external library call. Unordered-atomic variants transfer element_size chunks atomically under shared backing guard, alignment and length multiple checked; no whole-copy atomicity invented.',
        required_fields='kind dst src_or_byte length dst_align src_align volatile atomic_element_size',
        bindings=['memory.access', 'atomic.access']),
    'vector.fixed': dict(target='fixed_lane_expansion',
        semantics='Finite lane loops. VP active iff mask[lane] && lane<EVL; inactive arithmetic result poison unless merge/passthrough explicitly supplied; inactive memory/division lanes do not evaluate addresses/divisors or cause traps. Gather/scatter use lane source order for chosen deterministic refinement, completed lane effects retained on first fault. Reductions use source lane left fold with explicit start, preserving ordered FP contract; reassociation freedoms need not be used. Compress/expand consume active lanes in increasing order. Interleave/deinterleave/reverse/splice/shuffle are exact index permutations with component shadow. Scalable types require separately admitted vscale profile.',
        required_fields='opcode vector_types operands mask evl passthrough', bindings=['aggregate', 'fp', 'memory', 'division']),
    'coroutine.presplit': dict(target='logical_coroutine_frame',
        semantics='Exact phase-specific pinned Switch pipeline in coroutines.md; portable DL before passes, FIRST private E-slot SSA and preSplit present-E liveness. Header code tokens have portable fixed void(data_ptr) signature, param_noundef[true]. Selected P2014 aligned allocation preserves actual custom/fallback/nothrow/matching-delete and null-first path; actual nonnull FrameAlign before header. Split BEFORE logical journal instrumentation; partial-child process ownership protocol R042, never activation journal in ordinary frame. Commit continuation and detach journal BEFORE await_suspend/handle publication; resumer gets fresh current-thread claim. coro.size/align final frame geometry, inactive frame module/code leases retained. Destroy exact current cleanup once then matching deallocation/revocation. Symmetric transfer checked musttail. Final residual coroutine is compiler failure, not unsupported required source.',
        required_fields='frame_layout promise_layout resume destroy state cleanup_program allocation_policy', bindings=['memory', 'call', 'logical-eh']),
    'raw.integer_intrinsic': dict(target='bitvector_expansion',
        semantics='Exact bitvector math: carry/overflow pair computed without poison on ordinary overflow, saturation clamps, countzero zero flag respected, funnel shifts modulo width, abs MIN poison conditional, high multiply takes upper width bits of signed/unsigned2w product, scmp/ucmp returns -1/0/1; pdep/pext enumerate mask set bits low-to-high, clmul is XOR polynomial product truncated to width.',
        required_fields='opcode width operands immediate_flags', bindings=['integer']),
    'pointer.intrinsic': dict(target='pointer_offset_or_identity',
        semantics='ptrmask ANDs address bits while retaining original allocation provenance, never expands bounds; ssa.copy copies arbitrary typed operand0 and all component shadow, not pointer-only. launder/strip invariant group retain pointer address/provenance while resetting/preserving optimizer invariant identity per opcode; structured.gep indexes admitted explicit physical field layout with elementtype, never host layout. load.relative/type.checked.load.relative require an optional relative-pointer profile and diagnose; protected.field.ptr requires optional encoded-storage profile and diagnoses, never identity.',
        required_fields='opcode operands storage_layout', bindings=['pointer', 'gep', 'memory']),
    'stack.intrinsic': dict(target='stack_mark_restore_allocate',
        semantics='Activation-owned monotonic allocation sequence. stacksave returns opaque current mark; restore revokes every later allocation and journal registration, marks cannot cross activation/thread/generation. Preallocated setup reserves typed argument storage, arg selects one field, teardown consumes ticket exactly once; invoke cleanup invalidates storage after exceptional completion.',
        required_fields='opcode activation mark signature layout ticket', bindings=['memory', 'call']),
    'lifetime.intrinsic': dict(target='lifetime_change',
        semantics='lifetime.start/end revokes/creates declared guest object interval validity and poison shadow; invariant.start/end promise memory immutability for specified interval and scope, retained through optimizer then optional proof metadata only; violations are source UB, no host memory assumption.',
        required_fields='opcode pointer size lifetime', bindings=['memory']),
    'tls.intrinsic': dict(target='tls.address',
        semantics='LLVM threadlocal.address is IntrNoMem+Speculatable: exact tls_address_raw import returns issued stable preregistered guest TLS slot address for logical thread/modulegeneration, without guest initialization, backing materialization, blocking or catchable exception. TLS reservations occur before thread/module publication. R040 preserves the ORIGINAL source provider init call/invoke or weak-wrapper absence and normal/unwind CFG; raw lowering injects no extra initializer. A dedicated portable frontend may select qualified tls_initialize INSTEAD once, never both routes. Existing high-level initializing core TLS form is not a silent alias for the raw LLVM intrinsic. Retain module/object leases; native TLS model hints erased.',
        required_fields='entity thread generation offset storage_layout', bindings=['memory']),
    'fenv.intrinsic': dict(target='fenv.access',
        semantics='LLVM env/mode operands/results are target-private scalar i64: env=source roundcode|flags mask0xC3F, mode=source roundcode mask0xC00, all reserved bits zero. LLVM get/set.rounding use FLT_ROUNDS0zero/1nearest-even/2up/3down, NOT source FE codes; ambient4 rejects, per-operation nearest-away remains. Copyable snapshot is not current-thread authority or host fenv_t; source32-B representation uses fenv_pack->raw256 / fenv_unpack->snapshot+i1. Invalid unpack/word rejects before state mutation. Full env restore uses fenv_set/default; mode/round setters use exact fenv_set/mode_only to preserve CURRENT flags at one commit, never read-old-flags/fullrestore compound. Resetenv sets round0,flags0; resetmode only round0. Private diagnostic policy is excluded.',
        required_fields='opcode thread environment_value', bindings=['fp']),
    'varargs.intrinsic': dict(target='varargs.pack_access', semantics='Use accepted32-B va_list/32-B typed entry headers, owning activation/thread cookie and checked promoted nominal identities; va_copy independent cursor; va_end invalidates. Never host va_list.', required_fields='opcode list arguments signature activation', bindings=['varargs']),
    'eh.intrinsic': dict(target='eh.type_selector', semantics='eh.typeid.for maps admitted RTTI nominal identity to one consistent positive semantic selector within its enclosing function (not module/private handler ID); no host RTTI pointer conversion. eh.unwind.init publishes logical unwind availability without executing cleanup/search.', required_fields='opcode abi_type region', bindings=['logical-eh']),
    'typecheck.intrinsic': dict(target='descriptor_type_test', semantics='Resolve !type sets to admitted ABI-compatible vtable/code entries+offsets. type.test checks membership without dereference, type.checked.load performs checked load and returns token+membership bool. Relative forms decode guest relative relocation. Unknown metadata/type set is admission failure, not false success.', required_fields='opcode pointer offset abi_type_set', bindings=['memory', 'call']),
    'assumption.intrinsic': dict(target='assumption', semantics='Validate assume condition/bundles and preserve promises through final LLVM optimization; subsequent portable plans use no omitted promises. expect returns value, noalias.scope.decl introduces activation-local scoped alias identity; arithmetic.fence prevents later reassociation and returns operand.', required_fields='opcode operands bundles', bindings=['integer']),
    'no_effect.intrinsic': dict(target='copy_or_no_effect', semantics='donothing/fake_use/prefetch/annotations/reloc_none/pcmarker/pseudoprobe create no guest effects; is.constant chosen false when not proven true; allow runtime/sanitizer checks chosen true; do not suppress required sanitizer behavior through a false choice.', required_fields='opcode operands', bindings=[]),
    'trap.intrinsic': dict(target='diagnostic_trap', semantics='trap/ubsantrap/looptrap terminate execution at exact operation with reason code. No instruction after terminal trap commits. Resumable debugtrap is a separately diagnosed optional debugger profile, not this terminal operation.', required_fields='opcode reason location', bindings=['ub']),
    'effect.intrinsic': dict(target='effect_barrier', semantics='Opaque side effect is neither deleted nor reordered across other observable operations; no memory bytes or host IO invented.', required_fields='location', bindings=[]),
    'objectsize.intrinsic': dict(target='conservative_extent_bound', semantics='Baseline exact conservative refinement: minimum returns0; maximum returns result-width all-ones except address-space0 null with null_is_unknown=false returns0. This remains a valid lower/upper bound whether dynamic=true or false, requires no dereference/liveness probe and introduces no poison-consuming branch (select on pointer equality, or freeze condition). Optimizer-proven exact source extents may replace these bounds before lowering. Never query host malloc size; separately admitted stronger extent analysis is optional.', required_fields='pointer min null_unknown dynamic result_width', bindings=['integer', 'pointer', 'select']),
    'counter.intrinsic': dict(target='constant_zero', semantics='Baseline readcyclecounter/readsteadycounter return u64 zero, explicitly permitted by pinned LangRef for unsupported backends. No hardware counter, frequency or clock-service support is implied. Hosted clock services are distinct; a future nonzero counter profile requires its own accepted runtime contract.', required_fields='opcode', bindings=[]),
    'metadata.debug': dict(target='optional_debug', semantics='annotation/ptr.annotation return exact operand0 including component poison/provenance; var.annotation/codeview/debug void forms produce no guest value/effect. Translate source locations/variable lifetime/annotation strings to optional metadata; no source-defined annotation behavior invented and no change to semantic required sections or module content hash.', required_fields='opcode operands records', bindings=['aggregate']),
}
