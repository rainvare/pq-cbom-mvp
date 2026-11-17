"""Tests del cliente OSV (parseo con red simulada) y extracción de versiones."""

from pq_cbom import manifest_scanner, osv


def test_clean_version():
    assert manifest_scanner._clean_version("^8.5.1") == "8.5.1"
    assert manifest_scanner._clean_version(">=1.2.3") == "1.2.3"
    assert manifest_scanner._clean_version("v1.13.0") == "1.13.0"


def test_extract_package_specs(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\nrequests>=2.31\n")
    (tmp_path / "package.json").write_text('{"dependencies":{"elliptic":"^6.5.0"}}')
    specs = manifest_scanner.extract_package_specs(tmp_path)
    by_name = {s["name"]: s for s in specs}
    assert by_name["pycrypto"]["version"] == "2.6.1"
    assert by_name["pycrypto"]["ecosystem"] == "PyPI"
    assert by_name["elliptic"]["ecosystem"] == "npm"


def test_query_specs_parses_batch(monkeypatch):
    specs = [{"name": "pycrypto", "version": "2.6.1", "ecosystem": "PyPI"}]

    def fake_post(url, payload, timeout=20):
        return {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]}

    def fake_get(url, timeout=20):
        return {"summary": "Buffer overflow", "database_specific": {"severity": "CRITICAL"}}

    monkeypatch.setattr(osv, "_post_json", fake_post)
    monkeypatch.setattr(osv, "_get_json", fake_get)

    res = osv.query_specs(specs)
    assert len(res.vulns) == 1
    v = res.vulns[0]
    assert v.vuln_id == "GHSA-xxxx"
    assert v.severity == "CRITICAL"
    assert "overflow" in v.summary.lower()


def test_query_specs_empty():
    res = osv.query_specs([])
    assert res.vulns == []
    assert res.queried == 0


def test_severity_of_cvss():
    detail = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert "9.8" in osv._severity_of(detail)
