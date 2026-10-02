# Changelog

## 4.5.0 - 2026-10-02

### Changed
- Hardened the Local Group Policy reset flow so local Registry.pol results are cleaned even when domain, Entra ID or MDM management indicators are detected.
- Added backup and controlled cleanup of the documented Local Group Policy Preferences history stores.
- Kept Active Directory, Microsoft Entra ID and MDM policy outside the reset scope.
- Kept the reset operation free of forced Registry ACL rewriting, ownership changes and recursive permission repair.
- Extended reset verification to include Group Policy Preferences history cleanup.
- Updated the project version to 4.5.0.

### Safety
- The reset still does not disable Windows services, alter firewall rules, delete accounts, modify scheduled tasks or remove arbitrary Registry policy roots.
- Remote organisation policy may be reapplied after the local reset.

## 4.3.8 - 2026-10-01

### Changed

- Removed the confusing D1 backup deletion syntax.
- [D] now opens the numbered backup list for individual deletion.

## 4.3.7 - 2026-10-01

### Changed

- Backup numbers now restore immediately when entered from option [3].
- Individual backup deletion is selected through [D] and then a numbered backup.
- Delete-all remains available with A.
- Removed the secondary action menu for a selected backup.

## 4.3.5 - 2026-10-01

### Changed

- Grouped backup restore and backup cleanup under main-menu option [3].
- Removed the separate top-level backup cleanup option; the cleanup scope and preservation rules are unchanged.

## 4.3.4 - 2026-10-01

### Added

- Added a dedicated main-menu option to delete all PolicyReset backup artefacts.
- Backup cleanup removes only LocalGroupPolicy, Registry and backup-manifest.json from PolicyReset sessions.
- Diagnostic reports, operation reports and logs are preserved.

## 4.3.3 - 2026-10-01

### Fixed

- Replaced the PowerShell/.NET Registry permission-repair path with native Windows security APIs in the elevated PolicyReset process.
- Protected Registry trees are repaired key-by-key using SeTakeOwnershipPrivilege, SeBackupPrivilege and SeRestorePrivilege before recursive deletion.
- Temporary access is restricted to the local Administrators group and SYSTEM; no Everyone access is granted.
- Failed deletion restores the captured owner, group and DACL state on Registry keys that remain.
- Empty Registry policy containers recreated by Windows are no longer counted as remaining policy data.
- Added a Windows integration test that exercises protected, read-only Registry permissions before native repair and deletion.

## 4.3.2 - 2026-10-01

### Fixed

- Protected Registry cleanup now enables SeTakeOwnershipPrivilege, SeBackupPrivilege and SeRestorePrivilege inside the PowerShell process that performs the repair.
- If the PowerShell Registry provider cannot delete a repaired target, the same process attempts a fixed-target reg.exe deletion before restoring the original security descriptors on a final failure.
- Updated tests and audit documentation to cover the child-process privilege path and the corrected fallback order.

## 4.3.1 - 2026-10-01

### Fixed

- Protected Registry policy roots can now use a controlled permission-assisted removal path when normal key deletion is denied.
- Windows ownership, backup and restore privileges are enabled for the forced Registry path when available.
- Permission repair is restricted to the four fixed Registry policy roots and the local Administrators group; it does not grant access to Everyone.
- Security descriptors of remaining keys are restored on a failed permission-assisted deletion where possible.
- Registry access-denied roots are no longer treated as absent during final verification.

## 4.3.0 - 2026-10-01

### Added

- The main reset operation now removes the four Registry policy roots targeted by the original script, after creating a Registry backup.
- Registry policy root removal has normal and forced paths with post-removal verification.
- Registry backup sessions now record explicitly absent roots so restoration can preserve an absent state.
- Restore now restores the targeted Registry policy roots as well as the Local Group Policy stores.

### Changed

- Reset success now requires both Local Group Policy stores and all targeted Registry policy roots to be cleared.
- Reset reports include Registry root removal, failure, forced-removal and verification results.
- Security and README documentation now describe the expanded reset scope.

### Fixed

- Corrected reset report restart recommendation logic so it no longer references an undefined local variable.

## 4.2.5 - 2026-09-30

### Fixed

- Selecting `[0] EXIT` now closes the dedicated PowerShell console opened by `PolicyReset.pyw`.
- Running PolicyReset from an existing PowerShell session still leaves the parent terminal open.

## 4.2.4 - 2026-09-30

- Simplified Local Group Policy removal output to distinguish actual removals from an already-clear state.
- Corrected `gpresult` XML parsing to traverse complete UserResults and ComputerResults sections.
- Added explicit parser status reporting for valid XML, parse failures and missing RSoP result sections.
- Added dedicated JSON reports for restore and Group Policy refresh operations.
- Restore now verifies that resulting local stores match the selected backup state.
- Restore now clearly identifies backups that contain no Local Group Policy stores.
- Latest report now includes diagnostic, reset, restore and refresh reports.

# Changelog

## 4.2.3 - 2026-09-30

- Removed `gpupdate /force` from the Local Group Policy reset operation.
- Added a separate explicit menu action for `gpupdate /force`.
- Reset verification now focuses on the presence of the two Local Group Policy stores.
- Reset reports record that `gpupdate /force` was not run during reset.
- Restore continues to refresh Group Policy after restoring a backup.

## 4.2.2

- Corrected reset accounting so already-absent Local Group Policy stores are not counted as removed.
- Added explicit result states for no stores present and failed Group Policy refresh.
- Added `gpresult` XML collection and structured GPO extraction that is independent of the Windows display language.
- Stopped printing localised `gpupdate` command output directly into the English terminal UI; raw output is saved to `gpupdate.txt`.
- Added before-and-after Registry policy value reporting without treating those values as proof of a remaining Local Group Policy store.
- Created separate operation session directories for diagnosis and reset actions to preserve audit history.
- Restricted Restore backup selection to sessions that actually contain a Local Group Policy backup.

## 4.2.1

- Fixed `.pyw` double-click execution so the application requests UAC elevation before opening PowerShell.
- Removed the manual instruction to reopen PowerShell as Administrator.
- Added automatic elevation when `PolicyReset.pyw` is launched from a non-elevated PowerShell session.
- Validated the `ShellExecuteW` return value so launch failures are reported instead of being treated as successful.
- Corrected Local Group Policy restore so the selected backup replaces the current store instead of merging into it.
- Extended reset reports with forced-removal and remaining-failure details.

## 4.2.0

- Renamed the application to `PolicyReset.pyw`.
- Kept the application terminal-only.
- Added a `.pyw` bootstrap for double-click execution that opens a persistent PowerShell console.
- Direct execution with `python.exe PolicyReset.pyw` remains in the current PowerShell console.
- Removed GUI dependencies and form windows.
- Kept terminal `Y/N` confirmations.
- Preserved backup, Local Group Policy removal, forced-removal and verification workflows.
