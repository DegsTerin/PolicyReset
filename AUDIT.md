# PolicyReset 4.3.0 Audit Notes

- Local Group Policy reset does not run `gpupdate /force`.
- `gpupdate /force` is a separate explicit operation.
- Restore runs `gpupdate /force` only after replacing the selected local stores.
- `gpresult /x` is analysed structurally without relying on display language.
- Already-absent Local Group Policy stores and Registry policy roots are distinguished from successful removals.
- Restore verifies the resulting Local Group Policy stores and targeted Registry policy roots against the selected backup state.
- Diagnostic, reset, restore and refresh operations retain separate JSON reports.
- Active Directory, Microsoft Entra ID, MDM, Intune and other remote organisation-controlled policy are outside scope.
