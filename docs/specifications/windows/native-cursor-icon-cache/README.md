# Installed Win32u stock cursor and icon cache

The selected 64-bit Win32u entry uses two 16-byte counted descriptors and a
24-byte request. At offset 0 the request carries an optional USER handle. At
offset 8 it selects the resource kind. The three DWORDs from offset 12 specify
the desired format. Selectors 1 and 3 find the stock cursor and icon by
ordinal. A nonzero selector can reuse a valid handle. The selected catalogue
uses the relative priority observed for competing cached entries.

The installed Windows provider collects fixed queries on its converted GUI
helper. It retains stock resource identity, supported depth and default format
observations, and ordering. The emulator allocates opaque guest handles and
interprets guest pointers in guest memory. A successful lookup preserves the
guest's last-error and last-status values.

The two native Python controls ran with ARM64 Python on Windows build 29708.
Run each from its own directory. Each writes its observations to a new
`result.json`. The tracked JSON files contain the same rows, with one result
per line for review. The register-level replay matches handles by identity and
checks the error values, fault precedence, unaligned reads, and boundary sizes.
It exercises both 64-bit guest register layouts using controlled installed
inputs. Arbitrary application-created cursor/icon entries and paired WoW64 GUI
contexts require additional services.
