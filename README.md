# fobnail

## Usage

TBD

## Development

### pre-commit hooks

* Make sure you have Fobnail SDK v0.2.5 or later.

* Install hooks using `pre-commit.sh` script.

```
./pre-commit.sh install
```

* Enjoy automatic checks on each `git commit` action!

* (Optional) Run hooks on all files (for example, when adding new hooks or
  configuring existing ones):

```bash
./pre-commit.sh run --all-files
```

### TPM root CAs

`tpm_ek_roots` directory contains TPM root CAs which are required to verify
whether EK certificate comes from a TPM (and to complete platform provisioning
process). All certificates were downloaded from
[Microsoft](https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)
(downloaded in May 2022).

Only root certificates are installed (without intermediate), and only those with
RSA (Fobnail currently supports no other algorithms). All certificates were
converted from DER into PEM form.
