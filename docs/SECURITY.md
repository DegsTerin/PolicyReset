# Security

PolicyReset is a privileged Windows administration utility.

It operates on fixed Local Group Policy stores and four fixed Registry policy roots:

```text
%WinDir%\System32\GroupPolicy
%WinDir%\System32\GroupPolicyUsers
HKCU\Software\Policies
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies
HKLM\SOFTWARE\Policies
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
```

A backup is created before removal. The four Registry roots are deleted recursively after backup. Forced removal is available for failed Local Group Policy stores and failed Registry policy roots. Registry exports form part of the restoration backup.

The tool does not bypass or remove Active Directory, Microsoft Entra ID, MDM or other remote organisation-controlled policy.

Generated backups and reports may contain machine-specific information and must not be committed to a public repository.

`gpupdate /force` is not part of the removal operation. It is exposed separately so that a user can intentionally refresh available Group Policy when required.

## Policy refresh separation

`gpupdate /force` is intentionally not part of Local Group Policy removal. It is exposed as a separate explicit operation. Restore uses a refresh only after replacing the local stores so the restored policy can be processed.
