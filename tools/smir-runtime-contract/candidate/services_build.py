#!/usr/bin/env python3
"""Closed portable sysroot service contracts; no host calls or public new IDs."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / 'docs/specifications/smir/portable/schema/runtime/services-v1.json'
ROWS = []

POLICIES = {
    'all': 'Validate signature/capability/handle generation and all buffer guards before host effect; guest pointers never become unchecked host pointers. Zero-length spans need no dereference. Host errors convert explicitly; status0 success else positive portable errno; failure value0. Preserve structured native cause in runtime diagnostics, not guest errno alias. No runtime lock across host/guest callbacks. One operation ticket owns effect/result publication; cancellation only before irreversible effect, thereafter defer or publish a successful partial transfer. Resume never repeats effect.',
    'memory': 'Map returns zero-defined bytes with fresh object/generation; align positive power2, size>0, permissions R1/W2 only. Protect/unmap close admission and drain guard pins of every alias before changing mapping. No executable guest-data permission. Failed mutation leaves mapping unchanged.',
    'file': 'Paths counted strict UTF8, no NUL, length1..4096B; interpret selected guest personality namespace, never native path spelling by default. Handles process-owned generation checked, refcounts/dup share one open description/offset. Lock offset around one I/O ticket; partial read/write succeeds with exact byte count, at most65536B per call. EOF succeeds0. Failure after any bytes is success/count, native cause retained for next call. Close marks unusable before external close; no retry/reuse of same handle.',
    'file_control': 'All metadata/output structures are canonical little-endian service layouts, never host stat/dirent/timespec. Mutations commit once; read-only failures leave destination unchanged. Seek checked signed arithmetic no wrap, negative final offset EINVAL; regular file offsets independent of guest pointers. read_dir yields one complete entry or EOF0; insufficient nonzero capacity ERANGE and cursor unchanged; capacity0 peeks required bytes. read_link likewise capacity0 queries needed length, else whole result or ERANGE.',
    'clock': 'IDs0 monotonic,1 UTC Unix epoch (POSIX seconds, leap seconds excluded),2 process CPU,3 thread CPU. clock.read/resolution write time16; monotonic/CPU seconds nonnegative. clock.now converts checked seconds*10^9+nsec to u64 ns, overflow EOVERFLOW. sleep uses relative monotonic ns, UINT64_MAX not accepted; interruption EINTR writes exact remaining ns. Timezone uses immutable configured TZif artifact digest, not ambient host default; UTC profile always available.',
    'entropy': 'Fill entire <=1048576B destination atomically on successful host entropy; resource/error/cancel before copyout leaves unchanged. No PRNG fallback and no promise of deterministic bytes.',
    'thread': 'Spawn exact portable u64(data_ptr) token and arg in same process, publish handle only after worker reservation; TLS/fenv rounding+flags initially default, errno0, diagnostic policy inherited explicitly. Parallel workers permitted and required runtime capability. Join returns after target TLS/cleanup; self EDEADLK, concurrent secondjoin EINVAL, detached EINVAL; successful join consumes handle. Yield publishes exact next frontier. Detach consumes join right, not execution ownership.',
    'sync': 'wait32 address4B aligned in canonical shared atomic backing; compare and queue registration one transaction preventing lost wakeup. Return EAGAIN mismatch, ETIMEDOUT deadline, EINTR guest signal; spurious success allowed, caller loops. timeout u64ns0 poll,MAX infinite. wake selects oldest registration by monotonic wait ticket; count0 wakes0. No whole scheduler lock retained while blocking.',
    'process': 'All child arguments/environment copied from canonical spawn_spec before publication; returned handle identifies guest process. clone snapshot invokes coordinated all-worker safepoint, retains only caller thread in child, coherent shared/private/COW backing and handle inheritance, resets child pending signals/tickets; unexportable native/host resource EBUSY before publication. No direct host fork under runtime locks. wait consumes exited child handle only after cleanup; exit clean,quick,immediate modes use specified termination transaction; abort terminates without guest cleanup. Spawn never invokes ambient shell.',
    'module': 'Open exact verified artifact digest and explicit dependency deployment, no filesystem enumeration. Resolve all SCC/type/ABI/capabilities and personality/ISA before publication; constructors may callback outside locks. Close BUSY for own frame/callback/TLS/object/exception/native/code leases; close admission then drain others, reverse successful init finalization. symbol resolves exported namespace/name and actual admitted signature, never private ID equality.',
    'environment': 'Guest process environment protected by guest lock, counted UTF8 names/values no NUL; name nonempty no equals. get capacity0 returns required bytes excludingNUL, else complete value or ERANGE unchanged; absent ENOENT. set/unset snapshot atomically, never mutate host process environment. cwd is guest namespace state; locale baseline C only, other names ENOENT; ctype/formatting reside in guest libc.',
    'signal': 'Guest signals only: delivery queued to logical thread and observed at admitted safepoints, never unwind Rust or run arbitrary guest code in host async signal handler. set accepts default0/ignore1 or exact void(i32) code token with lease; signal numbers use selected personality table and admission. mask is canonical128B little-bitset with unavailable bits rejected; SIGKILL/SIGSTOP cannot be blocked on Linux/Darwin. raise synchronously queues current logical thread; fatal default invokes termination protocol. Host faults are runtime trap records, not inferred signal handlers.',
}


def add(name, params, *, policy, cap=None, buffers=(), constraints=(), value='zero',
        blocking='never', reentry='none', terminal=False, value_type='u64', descriptor='none'):
    ROWS.append({'namespace': 'smir.portable.v1', 'name': name, 'version': 1,
                 'params': [{'name': key, 'type': kind, 'noundef': False} for key, kind in params],
                 'results': [] if terminal else [{'type': 'u32', 'noundef': False},
                                                 {'type': value_type, 'noundef': False}],
                 'capability': cap or policy, 'policy': policy, 'descriptor_namespace': descriptor,
                 'buffers': [list(value) for value in buffers],
                 'constraints': [list(value) for value in constraints],
                 'success_value': value, 'blocking': blocking, 'reentry': reentry,
                 'terminal': terminal, 'cancellation': 'before_effect_else_defer',
                 'commit': 'single_ticket_result_after_effect_and_complete_copyout'})


add('memory.map', [('bytes','u64'),('alignment','u64'),('permissions','u32')], policy='memory',
    constraints=[('positive',0),('alignment',1),('mask',2,3)], value='guest_base', value_type='data_ptr')
add('memory.unmap', [('address','data_ptr'),('bytes','u64')], policy='memory', constraints=[('positive',1)], blocking='pin_drain')
add('memory.protect', [('address','data_ptr'),('bytes','u64'),('permissions','u32')], policy='memory', constraints=[('positive',1),('mask',2,3)], blocking='pin_drain')
add('file.open', [('path','data_ptr'),('length','u64'),('flags','u32'),('mode','u32')], policy='file',
    buffers=[('in',0,1,'path')], constraints=[('open_flags',2),('mask',3,0o7777)], value='file_handle',blocking='host')
for name in ['close','dup','flush']:
    add('file.'+name,[('handle','u64')],policy='file',constraints=[('handle',0)],
        value='file_handle' if name=='dup' else 'zero',blocking='host')
for name,direction in [('read','out'),('write','in')]:
    add('file.'+name,[('handle','u64'),('buffer','data_ptr'),('length','u64')],policy='file',
        buffers=[(direction,1,2,'stream')],constraints=[('handle',0)],value='bytes',blocking='host')
add('file.seek',[('handle','u64'),('offset','i64'),('whence','u32')],policy='file_control',cap='file',
    constraints=[('handle',0),('enum',2,[0,1,2])],value='offset',blocking='host')
add('file.truncate',[('handle','u64'),('bytes','u64')],policy='file_control',cap='file',constraints=[('handle',0)],blocking='host')
add('file.info',[('handle','u64'),('output','data_ptr')],policy='file_control',cap='file',
    constraints=[('handle',0)],buffers=[('out',1,128,'fixed')],blocking='host')
for name in ['stat','lstat']:
    add('file.'+name,[('path','data_ptr'),('length','u64'),('output','data_ptr')],policy='file_control',cap='file',
        buffers=[('in',0,1,'path'),('out',2,128,'fixed')],blocking='host')
for name in ['unlink','rmdir','chdir']:
    add('file.'+name,[('path','data_ptr'),('length','u64')],policy='file_control',cap='file',buffers=[('in',0,1,'path')],blocking='host')
add('file.mkdir',[('path','data_ptr'),('length','u64'),('mode','u32')],policy='file_control',cap='file',
    buffers=[('in',0,1,'path')],constraints=[('mask',2,0o7777)],blocking='host')
for name in ['rename','hard_link','symbolic_link']:
    add('file.'+name,[('source','data_ptr'),('source_length','u64'),('destination','data_ptr'),('destination_length','u64')],
        policy='file_control',cap='file',buffers=[('in',0,1,'path'),('in',2,3,'path')],blocking='host')
for name in ['read_link','open_dir']:
    params=[('path','data_ptr'),('length','u64')]
    buffers=[('in',0,1,'path')]
    if name=='read_link':
        params += [('output','data_ptr'),('capacity','u64')]
        buffers += [('out',2,3,'bounded')]
    add('file.'+name,params,policy='file_control',cap='file',buffers=buffers,
        value='dir_handle' if name=='open_dir' else 'bytes',blocking='host')
add('file.read_dir',[('handle','u64'),('output','data_ptr'),('capacity','u64')],policy='file_control',cap='file',
    buffers=[('out',1,2,'bounded')],constraints=[('handle',0)],value='bytes_or_eof0',blocking='host')
add('file.permissions',[('path','data_ptr'),('length','u64'),('mode','u32')],policy='file_control',cap='file',
    buffers=[('in',0,1,'path')],constraints=[('mask',2,0o7777)],blocking='host')
add('file.times',[('path','data_ptr'),('length','u64'),('times','data_ptr')],policy='file_control',cap='file',
    buffers=[('in',0,1,'path'),('in',2,32,'fixed')],blocking='host')
add('file.space',[('path','data_ptr'),('length','u64'),('output','data_ptr')],policy='file_control',cap='file',
    buffers=[('in',0,1,'path'),('out',2,32,'fixed')],blocking='host')
for name in ['read','resolution']:
    add('clock.'+name,[('clock','u32'),('output','data_ptr')],policy='clock',
        buffers=[('out',1,16,'fixed')],constraints=[('enum',0,[0,1,2,3])])
add('clock.now',[('clock','u32')],policy='clock',constraints=[('enum',0,[0,1,2,3])],value='nanoseconds')
add('clock.sleep',[('nanoseconds','u64'),('remaining','data_ptr')],policy='clock',
    buffers=[('out',1,8,'fixed')],constraints=[('maximum',0,2**64-2)],blocking='timer')
add('clock.timezone',[('artifact','data_ptr'),('length','u64')],policy='clock',buffers=[('in',0,1,'digest')])
add('entropy.fill',[('output','data_ptr'),('length','u64')],policy='entropy',
    buffers=[('out',0,1,'bounded')],constraints=[('maximum',1,1048576)],value='bytes',blocking='host')
add('thread.spawn',[('entry','code_ptr'),('argument','data_ptr'),('stack_bytes','u64')],policy='thread',
    constraints=[('thread_entry',0),('stack_size',2)],value='thread_handle',blocking='reserve')
for name in ['join','detach']:
    add('thread.'+name,[('thread','u64')],policy='thread',constraints=[('handle',0)],
        value='thread_result' if name=='join' else 'zero',blocking='thread' if name=='join' else 'never')
add('thread.yield',[],policy='thread')
add('thread.id',[],policy='thread',value='thread_identity')
add('thread.exit',[('result','u64')],policy='thread',terminal=True,reentry='guest_cleanup')
add('sync.wait32',[('address','data_ptr'),('expected','u32'),('timeout_ns','u64')],policy='sync',
    buffers=[('in',0,4,'fixed')],constraints=[('address_alignment',0,4)],blocking='atomic_wait')
add('sync.wake32',[('address','data_ptr'),('count','u32')],policy='sync',
    buffers=[('in',0,4,'fixed')],constraints=[('address_alignment',0,4)],value='woken_count')
add('process.spawn',[('specification','data_ptr'),('length','u64')],policy='process',
    buffers=[('in',0,1,'spawn')],value='process_handle',blocking='reserve')
add('process.clone',[('flags','u32')],policy='process',constraints=[('mask',0,0)],value='child_handle_parent_or0_child',blocking='all_worker_safepoint')
add('process.wait',[('process','u64')],policy='process',constraints=[('handle',0)],value='termination_u64',blocking='process')
add('process.id',[],policy='process',value='process_identity')
add('process.exit',[('status','i32'),('mode','u32')],policy='process',constraints=[('enum',1,[0,1,2])],terminal=True,reentry='guest_cleanup')
add('process.abort',[],policy='process',terminal=True)
add('module.open',[('artifact','data_ptr'),('length','u64')],policy='module',
    buffers=[('in',0,1,'digest')],value='module_handle',blocking='module',reentry='guest_init')
add('module.close',[('module','u64')],policy='module',constraints=[('handle',0)],blocking='module',reentry='guest_fini')
add('module.symbol',[('module','u64'),('namespace','data_ptr'),('namespace_length','u64'),
                     ('name','data_ptr'),('name_length','u64')],policy='module',
    buffers=[('in',1,2,'name'),('in',3,4,'name')],constraints=[('handle',0)],value='typed_token',value_type='code_ptr',descriptor='signature')
add('module.data_symbol',[('module','u64'),('namespace','data_ptr'),('namespace_length','u64'),
                          ('name','data_ptr'),('name_length','u64')],policy='module',
    buffers=[('in',1,2,'name'),('in',3,4,'name')],constraints=[('handle',0)],
    value='data_object',value_type='data_ptr',descriptor='nominal')
for name in ['get','set','unset']:
    params=[('name','data_ptr'),('length','u64')]
    buffers=[('in',0,1,'environment_name')]
    if name in ['get','set']:
        params += [('value','data_ptr'),('value_length','u64')]
        buffers += [('out' if name=='get' else 'in',2,3,'bounded' if name=='get' else 'text')]
    add('environment.'+name,params,policy='environment',buffers=buffers,value='bytes' if name=='get' else 'zero')
add('environment.cwd',[('output','data_ptr'),('capacity','u64')],policy='environment',buffers=[('out',0,1,'bounded')],value='bytes')
add('locale.select',[('category','u32'),('name','data_ptr'),('length','u64')],policy='environment',cap='locale',
    buffers=[('in',1,2,'locale')],constraints=[('enum',0,list(range(7)))])
add('signal.set',[('signal','u32'),('handler','u64')],policy='signal',cap='process',value='previous_handler')
add('signal.raise',[('signal','u32')],policy='signal',cap='process',reentry='guest_handler')
add('signal.mask',[('how','u32'),('input','data_ptr'),('output','data_ptr')],policy='signal',cap='process',
    buffers=[('in',1,128,'optional_fixed'),('out',2,128,'optional_fixed')],constraints=[('enum',0,[0,1,2])])

STRUCTURES = {
    'time16': {'size':16,'alignment':8,'format':'<qII','fields':['seconds','nanoseconds','reserved0'],
               'invariants':'0<=nanoseconds<1000000000; reserved0=0; signed Unix or monotonic seconds'},
    'file_info128': {'size':128,'alignment':8,'format':'<IIIIQQQQQIIqIIqIIqII16s',
        'fields':['revision1','kind','mode','flags','size','allocated','id_low','id_high','nlink',
                  'uid','gid','atime_seconds','atime_ns','atime_reserved0','mtime_seconds','mtime_ns',
                  'mtime_reserved0','ctime_seconds','ctime_ns','ctime_reserved0','reserved0'],
        'invariants':'kind0..7; mode&~07777=0; flags bit0 unknown_ownership bit1 unknown_id bit2 unavailable_times; unknownflagsreject; unavailable fields0 except uid/gidUINT32MAX; allreserved0'},
    'space32': {'size':32,'alignment':8,'format':'<QQQQ','fields':['capacity','free','available','reserved0'],
                'invariants':'0<=available<=free<=capacity in B; reserved0=0'},
    'dir_entry': {'size':16,'alignment':4,'format':'<IIII','fields':['revision1','kind','utf8_bytes','reserved0'],
                  'invariants':'header followed exactname bytes; noNUL, strictUTF8, no implicit terminator; kind0..7'},
}


def document():
    return {'format':'runtime_services_v1','version':1,'status':'candidate_contract',
            'namespace':'smir.portable.v1','status_domain':'portable_errno_linux_pinned_v1',
            'signature':'internal fixed portable nonvariadic; params/results/noundef exactly rows; abiNone; descriptor per-row returned-target namespace, not source C service signature',
            'policies':POLICIES,'structures':STRUCTURES,'records':ROWS}


if __name__=='__main__':
    OUTPUT.write_text(json.dumps(document(),indent=2)+'\n')
