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
