from pathlib import Path
import ctypes
import ast
import base64
import shutil
import os
import subprocess
import tempfile
import unittest
import uuid
import winreg
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "PolicyReset.pyw"


class PolicyResetSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = APP.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_application_exists_at_root(self):
        self.assertTrue(APP.is_file())

    def test_python_source_is_valid(self):
        ast.parse(self.source)

    def test_expected_version(self):
        self.assertIn('VERSION = "4.3.5"', self.source)

    def test_terminal_only(self):
        self.assertNotIn("tkinter", self.source.lower())
        self.assertNotIn("messagebox", self.source.lower())
        self.assertIn("input(", self.source)
        self.assertIn("while True:", self.source)

    def test_pyw_bootstrap_exists(self):
        self.assertIn("def _bootstrap_pyw()", self.source)
        self.assertIn("def _launch_persistent_powershell()", self.source)
        self.assertIn("ShellExecuteW", self.source)
        self.assertIn('"runas"', self.source)
        self.assertIn("--console", self.source)
        self.assertIn("-NoProfile -EncodedCommand", self.source)
        self.assertNotIn("-NoProfile -NoExit", self.source)

    def test_no_manual_admin_instructions(self):
        self.assertNotIn("Open PowerShell with 'Run as administrator'", self.source)
        self.assertNotIn("Press Enter to return to PowerShell...", self.source)
        self.assertNotIn("py .\\PolicyReset.py", self.source)

    def test_flat_main_menu(self):
        for item in (
            "[1] DIAGNOSE GROUP POLICY: Scan User and Computer and create report",
            "[2] REMOVE ALL LOCAL GROUP POLICY AND BACKUP: Remove and verify",
            "[3] RESTORE GROUP POLICY BACKUP: Restore a previous local policy backup",
            "[4] VIEW LATEST POLICYRESET REPORT: Display the latest operation report",
            "[5] REFRESH GROUP POLICY: Run gpupdate /force separately",
            "[6] DELETE ALL POLICYRESET BACKUPS: Remove backup artefacts and preserve reports",
            "[0] EXIT",
        ):
            self.assertIn(item, self.source)

    def test_fixed_local_gpo_paths(self):
        self.assertIn('"GroupPolicy"', self.source)
        self.assertIn('"GroupPolicyUsers"', self.source)

    def test_shell_execute_result_is_validated(self):
        self.assertIn("if result <= 32:", self.source)

    def test_gpresult_xml_collection_and_language_independent_parser(self):
        self.assertIn('"xml_report": None', self.source)
        self.assertIn('            "gpresult.exe",\n            "/x",\n', self.source)
        self.assertIn('def parse_gpresult_xml_applied_objects(', self.source)
        self.assertIn('"computerresults"', self.source)
        self.assertIn('"userresults"', self.source)
        self.assertNotIn("English gpresult parser", self.source)
        self.assertIn(".iter()", self.source)
        self.assertIn('"parse_failed"', self.source)
        self.assertIn('"no_result_sections"', self.source)

    def test_already_absent_stores_are_not_counted_as_removed(self):
        self.assertIn('already_absent: list[str] = []', self.source)
        self.assertIn('already_absent.append(str(directory))', self.source)
        self.assertNotIn('f"  Already absent: {len(already_absent)}"', self.source)
        self.assertIn("LOCAL GROUP POLICY ALREADY CLEAR", self.source)
        self.assertIn("Status: ", self.source)
        self.assertIn("Removal failed: ", self.source)
        self.assertIn('if before_count == 0 and registry_before_count == 0 and operation_clear:', self.source)

    def test_gpupdate_output_is_saved_not_echoed_to_ui(self):
        self.assertIn('output_file = session.directory / "gpupdate.txt"', self.source)
        self.assertNotIn('logger.info(stdout.strip())', self.source)

    def test_delete_all_backups_is_scoped_to_backup_artefacts(self):
        self.assertIn("BACKUP_ARTIFACT_NAMES = (", self.source)
        self.assertIn('"LocalGroupPolicy",', self.source)
        self.assertIn('"Registry",', self.source)
        self.assertIn('"backup-manifest.json",', self.source)
        self.assertIn("def find_backup_sessions(", self.source)
        self.assertIn("def delete_all_backups(", self.source)
        self.assertIn("Diagnostic reports, operation reports and log files are preserved.", self.source)
        self.assertIn('[6] DELETE ALL POLICYRESET BACKUPS: Remove backup artefacts and preserve reports', self.source)

    def test_registry_values_are_reported_separately(self):
        self.assertIn('"registry_policy_values_before": [', self.source)
        self.assertIn('"registry_policy_values_after": [', self.source)
        self.assertIn('registry_before = scan_policy_registry(logger)', self.source)
        self.assertIn('registry_after = scan_policy_registry(logger)', self.source)


    def test_registry_policy_roots_are_destructive_reset_targets(self):
        self.assertIn("def registry_policy_root_status(", self.source)
        self.assertIn("def remove_registry_policy_root(", self.source)
        self.assertIn("def force_remove_registry_policy_root(", self.source)
        self.assertIn('"registry_policy_roots_before": registry_roots_before', self.source)
        self.assertIn('"registry_policy_roots_after": registry_roots_after', self.source)
        self.assertIn("Registry policy roots are deleted recursively after backup.", self.source)

    def test_registry_force_path_repairs_permissions_without_everyone_acl(self):
        self.assertIn("def _enable_process_privileges(", self.source)
        self.assertIn('"SeTakeOwnershipPrivilege"', self.source)
        self.assertIn('"SeBackupPrivilege"', self.source)
        self.assertIn('"SeRestorePrivilege"', self.source)
        self.assertIn("def _registry_security_api(", self.source)
        self.assertIn('"HKCU": "CURRENT_USER"', self.source)
        self.assertIn('"HKLM": "MACHINE"', self.source)
        self.assertIn("GetNamedSecurityInfoW", self.source)
        self.assertIn("SetNamedSecurityInfoW", self.source)
        self.assertIn("ConvertSecurityDescriptorToStringSecurityDescriptorW", self.source)
        self.assertIn("ConvertStringSecurityDescriptorToSecurityDescriptorW", self.source)
        self.assertIn("S-1-5-32-544", self.source)
        self.assertIn("D:(A;;KA;;;BA)(A;;KA;;;SY)", self.source)
        self.assertNotIn("A;;GA;;;WD", self.source)
        self.assertNotIn("Everyone", self.source)
        self.assertNotIn("Add-Type -TypeDefinition", self.source)

    def test_permission_assisted_registry_cleanup_executes_on_windows(self):
        if os.name != "nt":
            self.skipTest("Windows-specific registry integration test.")

        function_names = (
            "_registry_hive",
            "_registry_security_api",
            "_registry_native_path",
            "_registry_security_sddl",
            "_registry_dacl_from_sddl",
            "_registry_set_owner_and_dacl",
            "_registry_restore_security_sddl",
            "enumerate_registry_key_paths",
            "remove_registry_key_tree",
            "_repair_registry_tree_permissions",
            "_restore_registry_tree_security",
        )
        functions = {
            "__builtins__": __builtins__,
            "Any": Any,
            "ctypes": ctypes,
            "wintypes": __import__("ctypes.wintypes", fromlist=["*"]),
            "winreg": winreg,
            "PolicyResetError": RuntimeError,
            "is_windows": lambda: True,
        }

        for name in function_names:
            node = next(
                node
                for node in ast.walk(self.tree)
                if isinstance(node, ast.FunctionDef)
                and node.name == name
            )
            exec(
                ast.get_source_segment(self.source, node),
                functions,
            )

        root_path = f"Software\\PolicyReset_CI_{uuid.uuid4().hex}"
        child_path = root_path + "\\Child"

        root = winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            root_path,
        )
        root.Close()

        child = winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            child_path,
        )
        winreg.SetValueEx(
            child,
            "Marker",
            0,
            winreg.REG_SZ,
            "PolicyReset CI",
        )
        child.Close()

        logger = type(
            "TestLogger",
            (),
            {
                "info": lambda self, message: None,
                "warn": lambda self, message: None,
            },
        )()

        original_sddl = functions["_registry_security_sddl"](
            "HKCU",
            root_path,
        )

        try:
            # Keep the key readable by Administrators but remove write access.
            functions["_registry_restore_security_sddl"](
                "HKCU",
                root_path,
                "O:BAG:BAD:(A;;KR;;;BA)(A;;KA;;;SY)",
            )
            functions["_registry_restore_security_sddl"](
                "HKCU",
                child_path,
                "O:BAG:BAD:(A;;KR;;;BA)(A;;KA;;;SY)",
            )

            repaired, backups, reason = functions["_repair_registry_tree_permissions"](
                "HKCU",
                root_path,
                logger,
            )
            self.assertTrue(repaired, reason)
            self.assertEqual(
                {root_path, child_path},
                set(backups),
            )

            functions["remove_registry_key_tree"](
                winreg.HKEY_CURRENT_USER,
                root_path,
            )

            with self.assertRaises(FileNotFoundError):
                winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    root_path,
                    0,
                    winreg.KEY_READ,
                )
        finally:
            try:
                functions["_registry_restore_security_sddl"](
                    "HKCU",
                    root_path,
                    original_sddl,
                )
            except Exception:
                pass

            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    root_path,
                    0,
                    winreg.KEY_ALL_ACCESS,
                ):
                    pass
                functions["remove_registry_key_tree"](
                    winreg.HKEY_CURRENT_USER,
                    root_path,
                )
            except OSError:
                pass



    def test_registry_access_denied_is_not_treated_as_absent(self):
        status = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "registry_policy_root_status"
        )
        status_text = ast.get_source_segment(self.source, status) or ""
        self.assertIn('if exists or state not in {"Absent", "Empty"}:', status_text)

    def test_registry_backup_records_absent_roots(self):
        self.assertIn('f"{base_name}.absent"', self.source)
        self.assertIn("Registry root was absent at backup time", self.source)
        self.assertIn('"registry_backup_success": registry_backup_ok', self.source)
        self.assertIn('"backup_success": registry_backup_ok and gpo_backup_ok', self.source)
        self.assertIn('if not registry_backup_ok:', self.source)


    def test_reset_removes_registry_policy_roots(self):
        reset = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "remove_all_local_group_policy"
        )
        calls = {
            node.func.id
            for node in ast.walk(reset)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertIn("remove_registry_policy_root", calls)
        self.assertIn("scan_policy_registry", calls)

    def test_restore_restores_registry_policy_roots(self):
        restore = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "restore_backup"
        )
        restore_text = ast.get_source_segment(self.source, restore) or ""
        self.assertIn('"import"', restore_text)
        self.assertIn("registry_backup_states", restore_text)
        self.assertIn("Registry policy roots: ", restore_text)
        self.assertIn('"import"', restore_text)

    def test_operation_sessions_are_distinct(self):
        self.assertIn('operation_session = create_session()', self.source)
        self.assertIn('diagnose(\n                    operation_session,', self.source)
        self.assertIn('remove_all_local_group_policy(\n                    operation_session,', self.source)

    def test_project_metadata_version(self):
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "4.3.5"', metadata)

    def test_all_project_local_function_calls_resolve(self):
        local_defs = {
            node.name
            for node in ast.walk(self.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.update(alias.asname or alias.name for alias in node.names)
        known = {
            "Path", "SystemExit", "ValueError", "any", "asdict", "bool", "dataclass",
            "enumerate", "getattr", "input", "int", "len", "print",
            "range", "repr", "set", "sorted", "str", "tuple"
        }
        called = {
            node.func.id
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        unresolved = sorted(called - local_defs - imported - known)
        self.assertEqual([], unresolved)

    def test_gpupdate_function_exists_as_separate_operation(self):
        self.assertIn("def refresh_group_policy(", self.source)
        self.assertIn('["gpupdate.exe", "/force"]', self.source)
        self.assertIn('timeout=300', self.source)
        self.assertIn('[5] REFRESH GROUP POLICY: Run gpupdate /force separately', self.source)

    def test_reset_does_not_call_gpupdate(self):
        reset = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "remove_all_local_group_policy"
        )
        calls = [
            node.func.id
            for node in ast.walk(reset)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        ]
        self.assertNotIn("refresh_group_policy", calls)

    def test_restore_still_refreshes_group_policy(self):
        restore = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "restore_backup"
        )
        calls = [
            node.func.id
            for node in ast.walk(restore)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        ]
        self.assertIn("refresh_group_policy", calls)


    def test_reset_ui_does_not_claim_to_refresh_group_policy(self):
        reset = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "remove_all_local_group_policy"
        )
        reset_text = ast.get_source_segment(self.source, reset) or ""
        self.assertNotIn("Refreshing User and Computer Group Policy", reset_text)
        self.assertIn("Verifying Local Group Policy and Registry policy roots", reset_text)

    def test_success_result_does_not_depend_on_gpupdate(self):
        self.assertIn('not remaining_stores', self.source)
        self.assertNotIn('and gpupdate_ok\n    ):\n        print("GROUP POLICIES REMOVED SUCCESSFULLY")', self.source)

    def test_reset_report_records_force_results(self):
        self.assertIn('"forced_removals": forced_removed', self.source)
        self.assertIn('"remaining_failures": [', self.source)

    def test_restore_does_not_merge_backup(self):
        self.assertIn("remove_directory_normal(current, logger)", self.source)
        self.assertIn("shutil.copytree(backup, current)", self.source)



    def test_latest_report_includes_all_operation_reports(self):
        self.assertIn('"diagnostic.json"', self.source)
        self.assertIn('"local_gpo_reset.json"', self.source)
        self.assertIn('"restore.json"', self.source)
        self.assertIn('"gpupdate.json"', self.source)

    def test_restore_verifies_selected_backup_state(self):
        self.assertIn("expected_present", self.source)
        self.assertIn("restored_state_matches", self.source)
        self.assertIn('"verification_passed"', self.source)
        self.assertIn('"operation_succeeded": operation_succeeded', self.source)

    def test_restore_identifies_empty_backup(self):
        self.assertIn("selected backup contains no Local Group Policy stores", self.source)

    def test_operation_reports_are_written(self):
        self.assertIn("def write_restore_report(", self.source)
        self.assertIn("def write_refresh_report(", self.source)
        self.assertIn("report = write_restore_report(", self.source)
        self.assertIn("report = write_refresh_report(", self.source)



    def test_gpresult_parser_executes_against_nested_namespaced_xml(self):
        helper = next(
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "_find_gpresult_name"
        )
        parser = next(
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "parse_gpresult_xml_applied_objects"
        )
        local_namespace = {"ET": __import__("xml.etree.ElementTree", fromlist=["ElementTree"]), "Path": Path}
        exec(ast.get_source_segment(self.source, helper), local_namespace)
        exec(ast.get_source_segment(self.source, parser), local_namespace)
        local_namespace["_xml_local_name"] = lambda tag: tag.rsplit("}", 1)[-1].lower()

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "gpresult.xml"
            report.write_text(
                """<Rsop xmlns=\"urn:test\">\n"""
                """  <ComputerResults><Wrapper><GPO><Name>Computer Policy</Name></GPO></Wrapper></ComputerResults>\n"""
                """  <UserResults><Wrapper><GPO Name=\"User Policy\" /></Wrapper></UserResults>\n"""
                """</Rsop>""",
                encoding="utf-8",
            )
            result = local_namespace["parse_gpresult_xml_applied_objects"](str(report))

        self.assertEqual((["Computer Policy", "User Policy"], "xml"), result)



    def test_restart_recommendation_is_conditional(self):
        self.assertIn('"restart_recommended": bool(', self.source)
        self.assertIn('before["remaining_count"] > 0', self.source)

    def test_reset_report_has_operation_status(self):
        self.assertIn('"operation_succeeded": (', self.source)
        self.assertIn('and not registry_roots_after', self.source)

    def test_refresh_report_records_output_file(self):
        self.assertIn('"output_file": str(session.directory / "gpupdate.txt")', self.source)



if __name__ == "__main__":
    unittest.main()