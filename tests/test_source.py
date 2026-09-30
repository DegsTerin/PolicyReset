from pathlib import Path
import ast
import tempfile
import unittest

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
        self.assertIn('VERSION = "4.2.4"', self.source)

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
        self.assertIn('if before_count == 0 and not still_failed and not remaining_stores:', self.source)

    def test_gpupdate_output_is_saved_not_echoed_to_ui(self):
        self.assertIn('output_file = session.directory / "gpupdate.txt"', self.source)
        self.assertNotIn('logger.info(stdout.strip())', self.source)

    def test_registry_values_are_reported_separately(self):
        self.assertIn('"registry_policy_values_before": [', self.source)
        self.assertIn('"registry_policy_values_after": [', self.source)
        self.assertIn('registry_before = scan_policy_registry(logger)', self.source)
        self.assertIn('registry_after = scan_policy_registry(logger)', self.source)

    def test_operation_sessions_are_distinct(self):
        self.assertIn('operation_session = create_session()', self.source)
        self.assertIn('diagnose(\n                    operation_session,', self.source)
        self.assertIn('remove_all_local_group_policy(\n                    operation_session,', self.source)

    def test_project_metadata_version(self):
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "4.2.4"', metadata)

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
            "Path", "SystemExit", "any", "asdict", "bool", "dataclass",
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
        self.assertIn("Verifying Local Group Policy stores", reset_text)

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
        self.assertIn('"operation_succeeded": not still_failed', self.source)

    def test_refresh_report_records_output_file(self):
        self.assertIn('"output_file": str(session.directory / "gpupdate.txt")', self.source)



if __name__ == "__main__":
    unittest.main()
    unittest.main()