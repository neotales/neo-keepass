# Encrypt and decrypt a field with age

Use `secrets get --age-encrypt` to encrypt one selected field. Use
`secrets set --age-decrypt` to decrypt input before storing it. Keep private
identity files separate from recipient public keys.

## Encrypt a field

Put one or more public age or SSH recipient keys in a local text file, one key
per line. Do not put private identities in that file. Then run:

```sh
nkp secrets get --key 'Services/Example' --field Password \
  --age-encrypt --age-recipient @recipients.txt --output password.age
```

The CLI prompts for the vault password. On success, `password.age` contains
armored ciphertext. The output is private and no-clobber: the command refuses
to replace an existing file. Without `--output`, ciphertext goes to stdout.

You can pass a public key directly with `-r KEY`. Repeat `-r` for multiple
recipients. `-r @PATH` reads a bounded recipient file. `-r gh:USER` fetches
that account's public SSH keys. An HTTPS URL can provide newline-separated age
or SSH public keys. These network lookups happen only when requested, require
`curl`, reject redirects, cap the response at 64 KiB, and time out after five
seconds. The CLI validates returned keys before encrypting.

## Decrypt input into a field

Choose a native age identity or an unencrypted SSH private key file:

```sh
nkp secrets set --key 'Services/Example' --field Password \
  --age-decrypt --age-identity identity.txt --file password.age
```

The command decrypts armored or binary age input, updates the selected field,
and saves the vault. It prompts for the vault password. Encrypted SSH private
key files are not supported.

Age flags belong to `secrets get` and `secrets set`. `field get` and `field
set` do not accept age flags; use the corresponding `secrets` command with
`--field` to select a custom field.

Never paste real identities or decrypted values into logs or support reports.
For complete command options, see [secrets commands](../reference/secrets.md).
