# Security

PolicyReset is a privileged Windows administration utility.

The current release is 4.3.8.

It operates on fixed Local Group Policy stores and four fixed Registry policy roots:

```text
%WinDir%\System32\GroupPolicy
%WinDir%\System32\GroupPolicyUsers
HKCU\Software\Policies
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies
HKLM\SOFTWARE\Policies
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
```

A backup is created before removal. The four Registry roots are deleted recursively after backup. Forced Registry removal enables the required token privileges in PolicyReset itself and uses native Windows security APIs for the fixed target, taking ownership and granting temporary FullControl only to the local Administrators group and SYSTEM. All discovered keys in the target tree are repaired before deletion. If deletion fails, saved owner, group and DACL descriptors are restored on keys that remain. Registry exports form part of the restoration backup.

The tool does not bypass or remove Active Directory, Microsoft Entra ID, MDM or other remote organisation-controlled policy.

Generated backups and reports may contain machine-specific information and must not be committed to a public repository.

`gpupdate /force` is not part of the removal operation. It is exposed separately so that a user can intentionally refresh available Group Policy when required.

## Policy refresh separation

`gpupdate /force` is intentionally not part of Local Group Policy removal. It is exposed as a separate explicit operation. Restore uses a refresh only after replacing the local stores so the restored policy can be processed.

## Protected Registry removal

The forced Registry path runs in the elevated PolicyReset process. It enables SeTakeOwnershipPrivilege, SeBackupPrivilege and SeRestorePrivilege, captures owner/group/DACL state, uses SetNamedSecurityInfoW for the fixed registry keys, and grants temporary FullControl only to the local Administrators group and SYSTEM. The saved security descriptors are restored on keys that remain after a failed deletion. It does not grant access to Everyone and it does not accept arbitrary Registry paths.

## Backup deletion

The backup deletion operation is restricted to PolicyReset-created backup artefacts inside `C:\ProgramData\PolicyReset\Sessions\`. It deletes only `LocalGroupPolicy`, `Registry` and `backup-manifest.json` items from backup sessions. Entering a backup number restores it immediately; [D] opens the numbered backup list for deletion; [A] deletes all backups. It does not delete diagnostic reports, operation reports or application log files. No arbitrary path is accepted.
