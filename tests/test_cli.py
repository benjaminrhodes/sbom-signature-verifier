import json
import pytest
from click.testing import CliRunner
from src.cli import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "verify" in result.output.lower()


def test_cli_parse_spdx(tmp_path):
    spdx_file = tmp_path / "sample.spdx.txt"
    spdx_file.write_text("""SPDXVersion: SPDX-2.3
DocumentName: test-bom

PackageName: test-pkg
PackageVersion: 1.0.0
""")
    runner = CliRunner()
    result = runner.invoke(cli, ["parse", str(spdx_file)])
    assert result.exit_code == 0
    assert "SPDX" in result.output
    assert "test-pkg" in result.output


def test_cli_parse_cyclonedx(tmp_path):
    cdx_file = tmp_path / "bom.json"
    cdx_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"name": "test-pkg", "version": "1.0.0"}],
            }
        )
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["parse", str(cdx_file)])
    assert result.exit_code == 0
    assert "cyclonedx" in result.output
    assert "test-pkg" in result.output


def test_cli_verify_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--help"])
    assert result.exit_code == 0


def test_cli_verify_spdx(tmp_path):
    spdx_file = tmp_path / "sbom.spdx"
    spdx_file.write_text("""SPDXVersion: SPDX-2.3
DocumentName: test

PackageName: pkg1
PackageDownloadLocation: https://example.com/pkg1
SHA256: abc123
""")
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(spdx_file)])
    assert result.exit_code == 0
