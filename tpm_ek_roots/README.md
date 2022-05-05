# TPM root CAs

This directory contains TPM root CAs which are required to verify whether EK
certificate comes from a TPM (and to complete platform provisioning process).
All certificates were downloads from
[Microsoft](https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates).

Only root certificates are installed (without intermediate), and only those with
RSA (Fobnail currently supports no other algorithms). All certificates were
converted from DER into PEM form.
