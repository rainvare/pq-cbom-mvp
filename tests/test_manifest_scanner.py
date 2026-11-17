"""Tests del collector de manifiestos de dependencias."""

from pq_cbom import manifest_scanner


def test_maps_algorithm_packages(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"bcrypt": "5.0.0", "elliptic": "6.5.0", "express": "4.0.0"}}'
    )
    result = manifest_scanner.scan_directory(tmp_path)
    ids = {m.rule_id for m in result.matches}
    assert "bcrypt" in ids
    assert "ECDSA" in ids   # elliptic -> ECDSA


def test_flags_weak_and_abandoned(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\nrequests==2.31\n")
    result = manifest_scanner.scan_directory(tmp_path)
    assert any("pycrypto" in w for w in result.weak_libs)


def test_lists_general_crypto_libs(tmp_path):
    (tmp_path / "requirements.txt").write_text("pyjwt==2.0.0\ncryptography==42.0\n")
    result = manifest_scanner.scan_directory(tmp_path)
    joined = " ".join(result.crypto_libs).lower()
    assert "pyjwt" in joined
    assert "cryptography" in joined


def test_go_mod_secp256k1(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module x\n\nrequire (\n\tgithub.com/ethereum/go-ethereum v1.13.0\n)\n"
    )
    result = manifest_scanner.scan_directory(tmp_path)
    assert any(m.rule_id == "ECDSA" for m in result.matches)


def test_pom_xml_bouncycastle(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>bcprov-jdk18on</artifactId>"
        "</dependency></dependencies></project>"
    )
    result = manifest_scanner.scan_directory(tmp_path)
    assert any("bcprov" in c.lower() for c in result.crypto_libs)
