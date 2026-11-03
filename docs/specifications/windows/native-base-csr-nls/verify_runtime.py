"""Check retained native runtime receipts against their exact owned source bytes."""
from pathlib import Path
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[3]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(name):
    return json.loads((ROOT / name).read_text())


def bound(receipt_name, manifest_name, subject):
    receipt = load(receipt_name)
    manifest = load(manifest_name)
    assert not receipt.get('error'), receipt.get('error')
    assert receipt['subject'] == subject
    assert receipt['original_native_jobs_restarted'] is False
    assert receipt['image_sha256'] == manifest['artifact']['sha256']
    assert receipt['source_manifest_sha256'] == digest((ROOT / manifest_name).read_bytes())
    assert receipt['ntdll_sha256'] == load('profile-v1.json')['ntdll_sha256']
    for path, expected in manifest['owned_sources'].items():
        assert digest((REPO / path).read_bytes()) == expected, path
    return receipt, manifest


def passed(row, count):
    assert row['exit_code'] == 0
    assert re.search(rf'test result: ok\. {count} passed; 0 failed; 0 ignored;', row['stdout'])


def main():
    user = 'S-1-5-21-432357189-4232641918-3742464398-1000'
    receipt, _ = bound('native-rust-arm64-v1.json', 'native-rust-source-v1.json', user)
    counts = [6, 3, 2, 2, 1, 1, 43]
    assert len(receipt['tests']) == len(counts)
    names = set()
    for row, count in zip(receipt['tests'], counts):
        passed(row, count)
        names.update(re.findall(r'^test ([^ ]+) \.\.\. ok$', row['stdout'], re.M))
    assert len(names) == 51 and sum(counts) == 58
    assert 'Validated installed ARM64 NtAlpcSendWaitReceivePort BASE NLS reply' in receipt['tests'][4]['stderr']
    startup, manifest = bound('native-startup-arm64-v1.json', 'native-startup-source-v1.json', user)
    assert digest((ROOT / 'startup-control.rs').read_bytes()) == manifest['artifact']['source_sha256']
    assert len(startup['tests']) == 1
    row = startup['tests'][0]
    assert row['exit_code'] == 0 and not row['stderr']
    terminal = [line for line in row['stdout'].splitlines() if line.startswith('TERMINAL ')]
    assert len(terminal) == 1
    assert 'sample=107047 instruction_budget_bound=6851072' in terminal[0]
    assert 'active_exception_seen=false' in terminal[0]
    assert 'Complete(Internal(' in terminal[0] and 'NtQuerySystemInformation class 134' in terminal[0]
    boundary = load('startup-boundary-v1.json')
    assert boundary['guest_success'] is False and boundary['terminal'] == terminal[0]
    print('verified: 58 native core case-runs/51 unique; CMD advanced to class134 and remains incomplete')
    if '--capi' in sys.argv[1:]:
        for context, subject in [('user', user), ('system', 'S-1-5-18')]:
            capi, _ = bound(f'native-capi-{context}-v1.json', 'native-capi-source-v1.json', subject)
            assert len(capi['tests']) == 1
            passed(capi['tests'][0], 243)
        print('verified: native CAPI243 in each subject')
    else:
        print('CAPI runtime receipts are outside this invocation; no native CAPI pass is inferred')


if __name__ == '__main__':
    main()
