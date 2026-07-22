import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate.py"


class ValidateCliTests(unittest.TestCase):
    def run_validator(
        self,
        files: dict[str, str],
        profile_content: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            surge_dir = Path(temp_dir) / "Surge"
            surge_dir.mkdir()
            for name, content in files.items():
                (surge_dir / name).write_text(content, encoding="utf-8")

            command = [sys.executable, str(VALIDATOR), "--surge-dir", str(surge_dir)]
            if profile_content is not None:
                profile = Path(temp_dir) / "Profile.conf"
                profile.write_text(profile_content, encoding="utf-8")
                command.extend(["--profile", str(profile)])

            return subprocess.run(
                command,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_rejects_app_bundle_path_without_trailing_slash(self) -> None:
        result = self.run_validator(
            {"AI.list": 'PROCESS-NAME,"/Applications/Claude.app"\n'}
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("App Bundle path must end with '/'", result.stdout)

    def test_rejects_hostname_only_anchored_url_regex(self) -> None:
        result = self.run_validator(
            {"Proxy.list": r"URL-REGEX,^(api\d+-)?qa\d+\.example\.com$" + "\n"}
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("anchored URL-REGEX must include a URL scheme", result.stdout)

    def test_rejects_semantic_conflict_between_policy_files(self) -> None:
        result = self.run_validator(
            {
                "Proxy.list": "DOMAIN-KEYWORD,stackblitz\n",
                "AI.list": "DOMAIN-SUFFIX,stackblitz.com\n",
            }
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("semantic conflict", result.stdout)
        self.assertIn("Proxy.list:1", result.stdout)
        self.assertIn("AI.list:1", result.stdout)

    def test_rejects_unregistered_policy_file(self) -> None:
        result = self.run_validator({"Unknown.list": "DOMAIN-SUFFIX,example.com\n"})

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unregistered policy file: Unknown.list", result.stdout)

    def test_accepts_comparison_port_expression(self) -> None:
        result = self.run_validator({"Direct.list": "SRC-PORT,>=50000\n"})

        self.assertEqual(result.returncode, 0, result.stdout)

    def test_accepts_current_surge_rule_types(self) -> None:
        result = self.run_validator(
            {
                "Proxy.list": (
                    "IP-ASN,13335\n"
                    "DOMAIN-WILDCARD,*.example.com\n"
                    "USER-AGENT,Example*\n"
                )
            }
        )

        self.assertEqual(result.returncode, 0, result.stdout)

    def test_rejects_rule_list_missing_from_profile(self) -> None:
        result = self.run_validator(
            {"JP.list": "DOMAIN-SUFFIX,example.jp\n"},
            profile_content="[Rule]\nFINAL,DIRECT\n",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("JP.list is not referenced by profile", result.stdout)


if __name__ == "__main__":
    unittest.main()
