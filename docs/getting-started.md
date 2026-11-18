# Create a vault and read a test entry

This tutorial creates a disposable vault, adds a sample entry, and reads the
sample username. The master password comes from a hidden prompt, not from the
command line.

Use a new directory so `init` cannot affect an existing vault:

```sh
mkdir "$HOME/nkeepass-demo"
chmod 700 "$HOME/nkeepass-demo"
nkp init "$HOME/nkeepass-demo/demo.kdbx"
```

If that directory already exists, choose another new name.

Type a strong master password at the prompt. On success, the vault is created
at the path you supplied. `init` refuses to overwrite an existing vault.
Password-only credentials also trigger an age-encrypted password backup; keep
the identity file described in the root README safe.

Now select this vault explicitly and create the entry. `ensure` creates
missing parent groups and the entry, while leaving an existing entry alone:

```sh
nkp --vault "$HOME/nkeepass-demo/demo.kdbx" \
  secrets ensure --key 'Demo/Example'
```

The command creates `Demo/Example` if it does not exist. It does not replace
an existing entry.

Set a sample username from a file. This leaves stdin attached to the terminal
for the hidden master-password prompt:

```sh
printf '%s' 'demo-user' > "$HOME/nkeepass-demo/username.txt"
nkp --vault "$HOME/nkeepass-demo/demo.kdbx" \
  secrets set --key 'Demo/Example' --field UserName \
  --file "$HOME/nkeepass-demo/username.txt"
```

The command prompts for the master password and stores the field in the vault.
This sample value is public test data, not a credential. If your environment
sets `NEO_KEEPASS_PASSWORD`, `NKP_PASSWORD`, or legacy `NKEEPASS_PASSWORD`,
the CLI uses the first present value in that order instead of prompting.

Read it back:

```sh
nkp --vault "$HOME/nkeepass-demo/demo.kdbx" \
  secrets get --key 'Demo/Example' --field UserName
```

Enter the same master password. The command prints `demo-user` to stdout.
Treat real output as sensitive: terminals, logs, and pipes can retain it.

List redacted entry metadata without revealing the field:

```sh
nkp --vault "$HOME/nkeepass-demo/demo.kdbx" secrets ls
```

The output is JSON Lines with entry metadata. `get` is an explicit disclosure;
`show` and `ls` provide metadata instead.

To remove the demo vault, first make sure its path is correct. The CLI does not
have a vault-delete command. Remove the file and its containing demo directory
with your operating system only after confirming they contain no needed data.

For the command contracts, see [secrets and entry operations](reference/secrets.md).
For vault selection order, see [choose the active vault](how-to/vault-selection.md).
