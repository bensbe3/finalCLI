"""Conservative dependency-usage evidence; never claims reachability."""

import json

import dependency_usage
from models import FileSet, Finding, Severity


def dependency(file: str, package: str) -> Finding:
    return Finding(
        file=file,
        line=1,
        rule_id="CVE-2026-12345",
        message="test advisory",
        severity=Severity.HIGH,
        tool="trivy",
        scan_type="dependencies",
        package=package,
        advisory_id="CVE-2026-12345",
    )


def test_javascript_direct_import_is_evidence_not_reachability(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    source = tmp_path / "src" / "app.ts"
    source.parent.mkdir()
    lockfile.write_text("{}", encoding="utf-8")
    source.write_text(
        'import { createBrowserRouter } from "react-router/dom";\n',
        encoding="utf-8",
    )
    fileset = FileSet()
    fileset.add("package-lock.json", lockfile)
    fileset.add(".ts", source)
    finding = dependency("package-lock.json", "react-router")

    dependency_usage.enrich([finding], fileset, tmp_path)

    assert finding.usage_status == "direct reference found"
    assert finding.usage_evidence == ["src/app.ts:1"]
    assert "not that the vulnerable function is reachable" in finding.usage_note


def test_no_direct_import_never_means_unreachable(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    source = tmp_path / "app.js"
    lockfile.write_text("{}", encoding="utf-8")
    source.write_text('import express from "express";\n', encoding="utf-8")
    fileset = FileSet()
    fileset.add("package-lock.json", lockfile)
    fileset.add(".js", source)
    finding = dependency("package-lock.json", "lodash")

    dependency_usage.enrich([finding], fileset, tmp_path)

    assert finding.usage_status == "no direct reference found"
    assert "not proof that it is unreachable" in finding.usage_note


def test_composer_uses_package_psr_namespace_mapping(tmp_path):
    lockfile = tmp_path / "composer.lock"
    source = tmp_path / "app" / "Export.php"
    source.parent.mkdir()
    lockfile.write_text(json.dumps({
        "packages": [{
            "name": "dompdf/dompdf",
            "autoload": {"psr-4": {"Dompdf\\": "src/"}},
        }],
    }), encoding="utf-8")
    source.write_text("use Dompdf\\Dompdf;\n", encoding="utf-8")
    fileset = FileSet()
    fileset.add("composer.lock", lockfile)
    fileset.add(".php", source)
    finding = dependency("composer.lock", "dompdf/dompdf")

    dependency_usage.enrich([finding], fileset, tmp_path)

    assert finding.usage_status == "direct reference found"
    assert finding.usage_evidence == ["app/Export.php:1"]


def test_unsupported_ecosystem_is_explicitly_unknown(tmp_path):
    lockfile = tmp_path / "pom.xml"
    lockfile.write_text("<project/>", encoding="utf-8")
    fileset = FileSet()
    fileset.add("pom.xml", lockfile)
    finding = dependency("pom.xml", "org.example:demo")

    dependency_usage.enrich([finding], fileset, tmp_path)

    assert finding.usage_status == "not supported"
    assert "not implemented" in finding.usage_note
