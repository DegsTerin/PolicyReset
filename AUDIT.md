# PolicyReset 4.3.5 Audit Notes

- Local Group Policy reset does not run `gpupdate /force`.
- `gpupdate /force` is a separate explicit operation.
- Restore runs `gpupdate /force` only after replacing the selected local stores.
- `gpresult /x` is analysed structurally without relying on display language.
- Already-absent Local Group Policy stores and Registry policy roots are distinguished from successful removals.
- Restore verifies the resulting Local Group Policy stores and targeted Registry policy roots against the selected backup state.
- Diagnostic, reset, restore and refresh operations retain separate JSON reports.
- Active Directory, Microsoft Entra ID, MDM, Intune and other remote organisation-controlled policy are outside scope.

- Protected Registry removal enables the required token privileges in the elevated PolicyReset process and uses native Windows security APIs for the fixed Registry tree.
- The permission repair is limited to the fixed four Registry policy roots and grants temporary FullControl only to the local Administrators group and SYSTEM.
- Original owner, group and DACL state is captured before repair and restored on keys that remain after a failed deletion.
- Empty Registry containers recreated without policy data are not treated as remaining policy data during verification.
- Registry access-denied states are not treated as an absent root during final verification.

- Backup management is grouped under main-menu option [3]. The cleanup action is constrained to LocalGroupPolicy, Registry and backup-manifest.json artefacts under the PolicyReset Sessions directory; reports and logs are preserved.
