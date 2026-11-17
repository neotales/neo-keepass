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

This is a deliberately limited subset of KeePass XML, not a claim that every
KeePass database can be exported losslessly. The CLI's explicit
`--allow-plaintext` path reveals protected text values, including passwords and
custom fields, and writes them as unprotected XML values. The library's default
`KdbxXml::export` remains restrictive and rejects any protected values; direct
library callers must deliberately choose `KdbxXml::export_allow_plaintext` to
allow plaintext text-field export. Protected binary attachments, public outer
header custom data, XML 1.0-forbidden characters, and other unsupported
XML/model data remain rejected rather than silently discarded. Validation and
encoding failures occur before the CLI output file is installed.

As with other private output files, a directory-durability diagnostic can be
reported after the file has already been installed atomically. In that case
the file may exist despite the command reporting failure; inspect the target
before retrying. The pre-install no-file guarantee applies only to validation
and encoding failures, not post-install durability uncertainty.

The CLI integration test constructs XML fixtures using this project's writer.
It is useful for routing, round-trip, and safety regression coverage but is
**not independently produced** and does not establish KeePass/KeePassXC
interoperability. No local KeePass/KeePassXC reference tool was available
during this change.
