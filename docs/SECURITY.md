# Security

PolicyReset is a privileged Windows administration utility.

It operates on the fixed Local Group Policy stores:

```text
%WinDir%\System32\GroupPolicy
%WinDir%\System32\GroupPolicyUsers
```

A backup is created before removal. Forced removal is restricted to failed Local Group Policy stores. Registry exports are supplemental and are recorded separately from the Local Group Policy store backup.

The tool does not bypass or remove Active Directory, Microsoft Entra ID, MDM or other remote organisation-controlled policy.

Generated backups and reports may contain machine-specific information and must not be committed to a public repository.

`gpupdate /force` is not part of the removal operation. It is exposed separately so that a user can intentionally refresh available Group Policy when required.

## Policy refresh separation

`gpupdate /force` is intentionally not part of Local Group Policy removal. It is exposed as a separate explicit operation. Restore uses a refresh only after replacing the local stores so the restored policy can be processed.
