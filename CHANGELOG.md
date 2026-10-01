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
