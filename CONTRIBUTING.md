# Contributing to RAX

## Contribution terms

Submit contributions to RAX under the repository's MIT license. Changes to
third-party files retain their existing terms. By submitting a contribution,
you confirm that you have authority to contribute it under those terms,
including any necessary employer or client authorization. Contributors retain
their copyright.

## Sources and generated material

For imported code, data, specifications or fixtures, provide the upstream URL,
revision/version, applicable license, original copyright notices, changes made,
and redistribution basis. Record a checksum for downloaded artifacts. Prefer
an authoritative link plus retrieval instructions for reference documents.
Do not submit confidential or partner-restricted inputs without publication
permission.

For generated files, identify the input revision/checksum and license,
generator revision, exact command, output paths and applicable output notices.
Update `THIRD_PARTY_NOTICES.md` and its `capi/` copy for applicable additions.

For guest binaries, provide exact source, configuration, patches and build
instructions, together with the applicable license/source-delivery record.
The same requirements apply to files used only for tests or documentation.

## Changes and validation

Follow [AGENTS.md](AGENTS.md) for architecture ownership and test selection.
Explain the failing behavior, the resulting behavior, and actual test execution.
For packaging or notice changes, see the
[licensing tools](docs/development/licensing/README.md) and run:

```sh
python3 tools/licensing/check.py
python3 -m unittest discover -s tools/capi -p 'test_*.py' -v
```

Keep PRs scoped, preserve other contributors' work, and include reproducible
technical evidence in review. Maintainers may close off-topic or abusive
threads. Report vulnerabilities through [SECURITY.md](SECURITY.md).
