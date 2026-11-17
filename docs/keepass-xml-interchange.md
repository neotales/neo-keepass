# KeePass XML interchange

The existing `import` and `export` commands keep their versioned JSON snapshot
format by default. `--format keepass-xml` explicitly selects KeePass XML:

```sh
nkeepass secrets import --file input.xml --format keepass-xml
nkeepass secrets export --output output.xml --format keepass-xml --allow-plaintext
```

The import path accepts unprotected KeePass XML and retains the existing
`--replace` and `--dry-run` behavior. It is not a KDBX reader: use the normal
vault-open credentials options for the destination vault, not for the XML file.

**Exported XML is plaintext.** XML export is refused unless
`--allow-plaintext` is present, writes only to a new private file (mode 0600
where supported), and never writes to stdout. Existing targets are not
overwritten. The opt-in acknowledges plaintext storage; it does not make the
output encrypted.

This is a deliberately limited subset of the core `KdbxXml` API, not a claim
that every KeePass database can be exported losslessly. Normal password-bearing
vaults are currently rejected: `KdbxXml` refuses protected values and cannot
represent values that require a KDBX protected inner stream. Public outer
header custom data is also rejected. These failures occur before the output
file is created. Unsupported XML/model data fails closed rather than being
silently discarded.

The CLI integration test constructs an unprotected XML fixture using this
project's `KdbxXml` writer. It is useful for routing and safety regression
coverage but is **not independently produced** and does not establish
KeePass/KeePassXC interoperability. No local KeePass/KeePassXC reference tool
was available during this change.
