# PE Format provenance

Issuing organization: Microsoft. Title: **PE Format**. Retrieved: 2026-09-27.
Canonical publication: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
Source copy: https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/Debug/pe-format.md
Source revision: the retrieved document's front matter; an immutable repository
commit was not resolved. SHA-256 of the retained source:
`a4e729294562932c5911c5aa554731279846cb51e1db25f1cb6c3d882d41307a`.

The source copy retains Microsoft documentation front matter and links.
Its repository licensing terms are available at
https://github.com/MicrosoftDocs/win32/blob/docs/LICENSE.
Consulted sections: Optional Header Windows-Specific Fields, Section Table,
Export/Import Tables, Base Relocation Table, TLS, Load Configuration,
Resource Data, and Exception Data.

Windows loader acceptance outside the specified format is unknown. The parser
implements format validation; these tests do not establish a modern Windows
loader differential oracle. HIGHADJ signed low-half addition and rounding have
explicit arithmetic regression tests; Microsoft's current table describes the
paired entry but does not give the rounding pseudocode.
