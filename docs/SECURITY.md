# Security

PolicyReset is a privileged Windows administration utility.

The current release is 4.3.2.

It operates on fixed Local Group Policy stores and four fixed Registry policy roots:

```text
%WinDir%\System32\GroupPolicy
%WinDir%\System32\GroupPolicyUsers
HKCU\Software\Policies
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies
HKLM\SOFTWARE\Policies
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
```

A backup is created before removal. The four Registry roots are deleted recursively after backup. Forced Registry removal first uses a controlled PowerShell/.NET security-descriptor path for the fixed target, enabling only the local Administrators group to obtain the required access. If that path fails, the existing reg.exe fallback is attempted. Registry exports form part of the restoration backup.

The tool does not bypass or remove Active Directory, Microsoft Entra ID, MDM or other remote organisation-controlled policy.

Generated backups and reports may contain machine-specific information and must not be committed to a public repository.

`gpupdate /force` is not part of the removal operation. It is exposed separately so that a user can intentionally refresh available Group Policy when required.

## Policy refresh separation

`gpupdate /force` is intentionally not part of Local Group Policy removal. It is exposed as a separate explicit operation. Restore uses a refresh only after replacing the local stores so the restored policy can be processed.

## Protected Registry removal

The forced Registry path enables the required Windows token privileges inside the PowerShell process that performs the ACL repair. It then uses the Windows Registry provider and .NET security descriptors for the fixed target only. It adds FullControl for the local Administrators group to the affected keys. If PowerShell deletion fails after the permission repair, the same elevated process attempts a fixed-target reg.exe deletion before restoring saved security descriptors on a final failure. It does not grant access to Everyone and it does not accept arbitrary Registry paths.
