"""Reproduce the finite 29704 CSR profile from its retained native archive."""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import struct
import sys
import zipfile
import base64

HERE = Path(__file__).resolve().parent
ARCHIVE_SHA256 = "6d6866212ccec57a522c94fc272d39394e7f82df11c18a8eef19d92c4f179956"
ARCHIVE_BYTES = 1232328

def published(name):
    if name.startswith(".task-evidence/"):
        return "docs/specifications/windows/native-csr-kernel-profiles/captured-29704-v1/" + Path(name).name
    return name

def collect(path):
    root = HERE.parents[3]
    helpers = runpy.run_path(str(HERE / "project-profile-v1.py"))
    require, captures, section = (helpers[name] for name in ("require", "captures", "section"))
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    require(path.stat().st_size == ARCHIVE_BYTES and sha(path.read_bytes()) == ARCHIVE_SHA256, "canonical archive identity")
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        require(len(names) == len(set(names)) == 65, "complete unique archive")
        require(all(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts for name in names), "member paths")
        binding = json.loads(bundle.read("native-source-v1.json"))
        receipt = json.loads(bundle.read("receipt.json"))
        recorded = json.loads(bundle.read("typed-profile-current-v1.json"))
        for name, expected in binding["source_frame"].items():
            require(sha((root / published(name)).read_bytes()) == expected, "retained producer " + name)
            require(sha(bundle.read("sources/" + Path(name).name)) == expected, "archived producer " + name)
        for program in binding["programs"]:
            image = bundle.read("executables/" + program["package_name"])
            require(len(image) == program["image"]["bytes"] and sha(image) == program["image"]["sha256"], "executable identity")
            pe = struct.unpack_from("<I", image, 0x3C)[0]
            require(image[pe:pe + 4] == b"PE\0\0", "PE signature")
            machine = {"arm64": 0xAA64, "x64": 0x8664, "x86": 0x14C}[program["caller_architecture"]]
            require(struct.unpack_from("<H", image, pe + 4)[0] == machine, "native caller machine")
        tools = json.loads(bundle.read("build/tool-identities-v1.json"))
        build_names = [name for name in names if name.startswith("build/") and name != "build/tool-identities-v1.json"]
        require(len(build_names) == 9 and tools["completed_native_images"] == 17 and tools["failed_compile_receipts_retained"], "compiler/linker receipt coverage")
        require(receipt['phase'] == 'finished' and receipt['images_unchanged'] and (not receipt.get('error')), 'terminal successful unchanged native capture')
        require(receipt['providers_before'] == receipt['providers_after'] and len(receipt['providers_before']) == 3, 'three stable physical provider bindings')
        require(len(binding['programs']) == len(receipt['runs']) == 20, 'fourteen controls plus six provider identities')
        logs, raw_logs, images = ({}, {}, [])
        for program, run in zip(binding['programs'], receipt['runs']):
            require(program['architecture'] == run['label'], 'native run identity/order')
            require(run['exit_code'] == 0 and run['stderr_bytes'] == 0, 'native observer result')
            raw = base64.b64decode(run['stdout_base64'], validate=True)
            require(sha(raw) == run['stdout_sha256'], 'native stdout identity')
            name = run['label']
            raw_logs[name] = raw
            logs[name] = raw.decode('utf-8').replace('\r\n', '\n')
            images.append(dict(kind=program['kind'], architecture=program['caller_architecture'], image=program['image'], stdout_sha256=run['stdout_sha256'], source=program['source']))
        metadata = []
        for abi, width in [('arm64', 8), ('x64', 8), ('x86', 4)]:
            provider = receipt['providers_before'][abi]
            require(('\\SyChpe32\\' if abi == 'x86' else '\\System32\\').lower() in provider['physical_path'].lower(), 'actual mapped physical provider family')
            for kind in ['metadata1', 'metadata2']:
                text = logs[kind + '-' + abi]
                dump = dict(captures(text))
                require(int(re.search('profile width=(\\d+)', text)[1]) == width, 'caller pointer width')
                require(dump['csr-pid-code'].hex() == provider['getter_code_hex'], 'metadata getter/physical provider correlation')
                selected = re.search('selected shared=([0-9A-F]+) statics=([0-9A-F]+) offset=([0-9A-F]+)', text)
                require(selected is not None, 'selected pointers')
                shared, statics, offset = (int(value, 16) for value in selected.groups())
                require(statics - shared == offset == 1872, 'CSR statics offset')
                peb, prefix = (dump['peb'], dump['selected-prefix'])
                major_offset, minor_offset, build_offset, session_offset = (280, 284, 288, 704) if width == 8 else (164, 168, 172, 468)
                kernel = [struct.unpack_from('<I', peb, major_offset)[0], struct.unpack_from('<I', peb, minor_offset)[0], struct.unpack_from('<H', peb, build_offset)[0]]
                session = struct.unpack_from('<I', peb, session_offset)[0]
                require(kernel == [10, 0, 29704] and session == 1, 'exact measured kernel/session')
                row = dict(architecture=abi, kind=kind, pointer_bytes=width, kernel=kernel, session=session, statics_offset=offset, getter_code_hex=dump['csr-pid-code'].hex(), prefix_sha256=sha(prefix), stdout_sha256=sha(raw_logs[kind + '-' + abi]))
                if width == 8:
                    server = struct.unpack_from('<Q', peb, 896)[0]
                    require(server == struct.unpack_from('<Q', prefix, 40)[0] == struct.unpack_from('<Q', prefix, 48)[0], 'native64 server aliases')
                    row['server_base'] = server
                pid = re.search('csr-pid-value value=([0-9A-F]+)', text)
                if kind == 'metadata2':
                    require(pid is not None, 'independent PID getter value')
                    row['server_pid'] = int(pid[1], 16)
                    require(row['server_pid'] > 0 and row['server_pid'] % 4 == 0, 'server PID')
                require('complete status=0 read-only=1' in text, 'readonly completion')
                metadata.append(row)
            pair = [row for row in metadata if row['architecture'] == abi]
            require(pair[0]['getter_code_hex'] == pair[1]['getter_code_hex'] and pair[0]['prefix_sha256'] == pair[1]['prefix_sha256'], 'independent metadata producers agree')
        arm64 = next((row for row in metadata if row['architecture'] == 'arm64' and row['kind'] == 'metadata2'))
        sections = [section(logs['section-' + abi], abi) for abi in ['arm64', 'x64', 'x86']]
        require(len({row['committed_sha256'] for row in sections}) == 1, 'all caller section snapshots agree')
        client_views = {}
        for abi in ['arm64', 'x64', 'x86']:
            text = logs['client-' + abi]
            require('SUMMARY calls=2' in text and len(re.findall('^CONNECT sample=\\d+ server=3 supplied=584 status=00000000 exception=00000000 returned=584 inside=0', text, re.M)) == 2, 'both native USER acquisitions')
            views = []
            for slot, expected_size in [(16, 2097152), (40, 32768)]:
                runs = []
                for match in re.finditer('^MAP slot=(\\d+) base=([0-9A-F]+) offset=(\\d+) bytes=(\\d+) state=([0-9A-F]+) protect=([0-9A-F]+) type=([0-9A-F]+) hex=([0-9A-F]*)(?: stable=(\\d+))?$', text, re.M):
                    raw_slot, address, offset, size, state, protection, kind, raw, stable = match.groups()
                    if int(raw_slot) != slot:
                        continue
                    offset, size, state, protection, kind = (int(offset), int(size), int(state, 16), int(protection, 16), int(kind, 16))
                    require(kind == 262144 and size > 0 and (size % 4096 == 0), 'mapped readonly allocation extent/type')
                    data = bytes.fromhex(raw)
                    require(state == 4096 and protection == 2 and (stable == '1') and (len(data) == size) or (state == 8192 and protection == 0 and (not data) and (stable is None)), 'stable committed readonly bytes or uncommitted reserve')
                    runs.append(dict(offset=offset, bytes=size, state=state, protection=protection, type=kind, captured_sha256=sha(data) if data else None))
                require(runs and runs[0]['offset'] == 0 and (sum((row['bytes'] for row in runs)) == expected_size), 'full selected allocation coverage')
                require(all((left['offset'] + left['bytes'] == right['offset'] for left, right in zip(runs, runs[1:]))), 'contiguous runs')
                require(re.search('^MAP-END slot=' + str(slot) + ' base=[0-9A-F]+ bytes=' + str(expected_size) + ' runs=' + str(len(runs)) + ' committed=\\d+$', text, re.M) is not None, 'allocation termination')
                views.append(dict(slot=slot, allocation_bytes=expected_size, runs=runs))
            client_views[abi] = views

        require(metadata == recorded["metadata_samples"], "independent metadata reprojection")
        require(sections == recorded["shared_section"] and client_views == recorded["client_views"], "full allocation reprojection")
        metadata_rows = metadata
        metadata = arm64
        getter = {"server_pid": arm64["server_pid"]}
        logs["secure"] = logs["secure-arm64"]
        logs["exchange"] = logs["exchange-arm64"]
        identities = [{"kind": row["label"], "stdout_sha256": row["stdout_sha256"]} for row in receipt["runs"]]
        secure_text = logs['secure']
        require('return ordinal=0 status=00000000' in secure_text and
                'complete captured=1 calls=1 exit=41' in secure_text, 'natural secure connection')
        secure = dict(captures(secure_text))
        port = secure['port-name-utf16'].decode('utf-16le')
        require(port == '\\Sessions\\1\\Windows\\ApiPort', 'selected session CSR port')
        require(secure['security-qos'].hex() == '000000000200000001010000', 'security QoS')
        require(secure['required-server-sid'].hex() == '010100000000000512000000', 'required System SID')
        require(len(secure['client-view-before']) == 48 and len(secure['server-view-after']) == 24, 'view widths')
        require(secure['server-view-after'] == bytes(24), 'cleared server view')
        require(struct.unpack_from('<I', secure['client-view-before'])[0] == 48 and
                struct.unpack_from('<Q', secure['client-view-before'], 24)[0] == 65536, 'client view geometry')
        require(int.from_bytes(secure['max-message-after'], 'little') == 952 and
                int.from_bytes(secure['connection-length-after'], 'little') == 48, 'connection output widths')
        server, statics, pid = struct.unpack_from('<QQQ', secure['connection-after'])
        require(server == metadata['server_base'] and statics - server == 0x750 and
                pid == getter['server_pid'], 'independent metadata/reply identity')
        require(secure['connection-after'][32:] == secure['connection-before'][32:], 'preserved information tail')

        exchange_text = logs['exchange']
        require('complete installed=1 entered=2 returned=2 exit=41' in exchange_text, 'natural USER exchange')
        returns = re.findall(r'^return ordinal=\d+ name=\w+ status=([0-9A-F]+)$', exchange_text, re.M)
        require(returns == ['00000000', '00000000'], 'successful protocol returns')
        entry = re.search(r'^entry ordinal=1 name=NtAlpcSendWaitReceivePort caller=[0-9A-F]+ args=([0-9A-F,]+)$', exchange_text, re.M)
        require(entry is not None, 'USER entry')
        arguments = [int(word, 16) for word in entry[1].rstrip(',').split(',')]
        require(len(arguments) == 8 and arguments[1] == 0x20000 and arguments[2] == arguments[4], 'synchronous flags and alias')
        require(arguments[3] == arguments[6] == arguments[7] == 0, 'no attributes or timeout')
        user = captures(exchange_text)
        send = next(raw for name, raw in user if name == 'send-message')
        before = [raw for name, raw in user if name == 'client-section-before-call'][-1]
        aliases = re.search(r'client-alias local=([0-9A-F]+) remote=([0-9A-F]+) size=(\d+)', exchange_text)
        require(aliases is not None, 'connection aliases')
        local, remote, size = int(aliases[1], 16), int(aliases[2], 16), int(aliases[3])
        require(size == 65536, 'pagefile connection backing size')
        capture_pointer = struct.unpack_from('<Q', send, 40)[0]
        offset = capture_pointer - remote
        require(0 <= offset <= size - 628, 'capture pointer bounds')
        capture = before[offset:offset + 628]
        require(len(capture) == 628 and struct.unpack_from('<I', capture)[0] == 628, 'capture extent')
        require(struct.unpack_from('<I', capture, 16)[0] == 1 and
                struct.unpack_from('<Q', capture, 32)[0] == 72, 'one capture pointer field')
        require(capture[40:624] == bytes(584), 'zero USER information input')
        require(len(send) == 88 and struct.unpack_from('<HH', send) == (48, 88), 'message widths')
        require(struct.unpack_from('<Q', send, 64)[0] == 3 and
                struct.unpack_from('<Q', send, 80)[0] == 584, 'USER selector and length')
        require(struct.unpack_from('<Q', send, 72)[0] == capture_pointer + 40, 'information pointer relocation')
        reply = dict(user)['receive-after']
        require(len(reply) == 88 and struct.unpack_from('<3H', reply) == (48, 88, 2), 'reply widths and type')

        report = dict(utc=recorded['protocol']['utc'],
            state='native-protocol-observed', kernel=metadata['kernel'], session=metadata['session'],
            architecture='arm64', selected_port=port, server_identity_correlated=True,
            secure=dict(status=0, client_view_bytes=48, server_view_bytes=24,
                        connection_bytes=48, maximum_message_bytes=952, statics_offset=0x750),
            exchange=dict(status=0, flags=0x20000, message_bytes=88, data_bytes=48,
                          allocation_bytes=628, header_bytes=40, information_bytes=584,
                          pointer_count=1, pointer_field_offset=72),
            native_images_unchanged=True, source_bound=True, observers=identities,
            allows_new_model_profile=False,
            scope='Current native ARM64 protocol only; full client allocations, physical compatibility-provider bindings and runtime/model qualification remain separate.')

        require(report == recorded["protocol"], "complete protocol reprojection")
        protocol = report
        for row in metadata_rows:
            row["selected_prefix_hex"] = dict(captures(logs[row["kind"] + "-" + row["architecture"]]))["selected-prefix"].hex()
        origins = {published(name): expected for name, expected in binding["source_frame"].items()}
        for image, program in zip(images, binding["programs"]):
            image["image"]["path"] = "executables/" + program["package_name"]
            candidates = [name for name, expected in origins.items() if expected == image["source"]["sha256"]]
            require(len(candidates) == 1, "unique retained source identity")
            image["source"]["path"] = candidates[0]
            for key in ("original_path", "original_source"):
                if key in image["source"]:
                    value = image["source"][key]
                    require("/docs/" in value, "original source is a retained repository path")
                    image["source"][key] = value[value.index("/docs/") + 1:]
        report = copy.deepcopy(recorded)
        report.update(metadata_samples=metadata_rows, shared_section=sections, client_views=client_views, protocol=protocol, providers=receipt["providers_before"], images=images)
        report["archive"] = dict(name="csr-29704-native-artifacts-v2.zip", bytes=ARCHIVE_BYTES, sha256=ARCHIVE_SHA256, scope="Separately retained canonical observation archive; executables and raw stdout are not reconstructed from this projection.")
        report["source_origins"] = origins
        report["compiler_binding"] = tools
        return report


def main():
    if not __debug__:
        raise ValueError("optimized validation rejected")
    if len(sys.argv) != 2:
        raise ValueError("usage: project-29704-v1.py retained-native-results.zip")
    print(json.dumps(collect(Path(sys.argv[1])), indent=2))


if __name__ == "__main__":
    main()
