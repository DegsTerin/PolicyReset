# PolicyReset 4.5.0 Audit Notes

## Scope

PolicyReset targets the Windows Local Group Policy stores:

- `%WINDIR%\\System32\\GroupPolicy`
- `%WINDIR%\\System32\\GroupPolicyUsers`

It also removes Registry values that are explicitly represented by the local:

- `Machine\\Registry.pol`
- `User\\Registry.pol`

The reset does not recursively delete broad Registry policy roots and does not attempt to remove Active Directory, Microsoft Entra ID, MDM, Intune or other remote organisation-controlled policy.

## Destructive-operation safety

- A backup is created before reset or restore.
- The reset uses normal file and Registry APIs only.
- The reset does not call `takeown.exe`, `icacls.exe`, forced Registry ACL repair, or forced Registry-tree deletion.
- The reset does not disable Windows services, firewall rules, scheduled tasks, accounts or unrelated system configuration.
- Group Policy Preferences History is backed up but deliberately preserved during reset. Microsoft documents this location as a local database used by Group Policy Preferences, and the Group Policy client can recreate the repository if it is lost. Deleting it automatically could therefore change subsequent preference-processing behaviour.
- `gpupdate /force` is not run during reset.
- `gpupdate /force` remains a separate explicit operation.

## Registry.pol handling

Registry.pol is parsed according to Microsoft's documented format. The reset can safely target:

- normal Registry values represented by the local Registry.pol;
- `**Del.<valuename>`;
- `**soft.<valuename>`;
- `**DeleteValues`.

The reset does not reverse:

- `**DeleteKeys`;
- `**DelVals.`;
- `**SecureKey`.

Those instructions either describe deletion already performed by policy or security-descriptor behaviour. Reversing them automatically would require modifying keys or ACLs outside the narrow value-removal scope.

## Verification

The reset verifies:

- Local Group Policy stores after removal.
- Targeted Registry.pol values after removal.
- Any removal failures.
- Unsupported or malformed local Registry.pol files.
- Management indicators for domain, Entra ID and MDM.

Values that remain under broad Registry policy roots but were not represented by the local Registry.pol files are reported as out of scope. They are not treated as evidence that the local Registry.pol cleanup failed.

## Restore safety

Restore replaces the selected Local Group Policy directories after creating a safety backup.

Registry backup exports are imported with `reg.exe import` without first deleting the current Registry policy roots. If a backup recorded a root as absent, the current root is preserved rather than deleted. This is intentionally non-destructive, so Registry restoration is not guaranteed to recreate an exact historical state.

Restore may run `gpupdate /force` after restoration. Remote organisation-controlled policy can therefore be reapplied by Windows.

## Test coverage

The source-level suite checks:

- Python syntax and project metadata.
- Fixed Local Group Policy targets.
- Backup requirements.
- Registry.pol parsing and `**DeleteValues`.
- Separation of reset and `gpupdate /force`.
- Absence of Registry ACL repair in reset and restore paths.
- Safe Registry import during restore.
- Language-independent `gpresult` XML parsing.
- Management-boundary handling.
- Report generation and operation status.

The CI runs on Windows and executes the complete unittest suite.

## Residual limitations

No software can guarantee that every observable effect of Group Policy is reversible from the client. Some Group Policy Client-Side Extensions can change services, scheduled tasks, security settings, files, accounts, network configuration or other state outside Registry.pol. PolicyReset intentionally does not attempt broad reverse-engineering of those effects because doing so would increase the risk of damaging unrelated Windows configuration.

A final application-level verification may require a restart and a fresh Group Policy diagnosis. Remote policy may also be reapplied after connectivity or a Group Policy refresh.
