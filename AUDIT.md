# PolicyReset 4.3.2 Audit Notes

- Local Group Policy reset does not run `gpupdate /force`.
- `gpupdate /force` is a separate explicit operation.
- Restore runs `gpupdate /force` only after replacing the selected local stores.
- `gpresult /x` is analysed structurally without relying on display language.
- Already-absent Local Group Policy stores and Registry policy roots are distinguished from successful removals.
- Restore verifies the resulting Local Group Policy stores and targeted Registry policy roots against the selected backup state.
- Diagnostic, reset, restore and refresh operations retain separate JSON reports.
- Active Directory, Microsoft Entra ID, MDM, Intune and other remote organisation-controlled policy are outside scope.

- Protected Registry removal enables the required token privileges inside the PowerShell process that performs the cleanup, not only in the Python parent process.
- The permission repair is limited to the fixed four Registry policy roots and targets the local Administrators group rather than Everyone.
- If PowerShell deletion fails after ACL repair, the same process attempts the fixed-target reg.exe fallback before restoring saved security descriptors on a final failure.
- Registry access-denied states are not treated as an absent root during final verification.
