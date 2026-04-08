"""Basic scanner tests."""

import textwrap
from pathlib import Path
import pytest
from sourceguard.scanner import scan
from sourceguard.entropy import high_entropy_strings


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(textwrap.dedent(content))
    return f


# ── Rule-based detection ─────────────────────────────────────── #

def test_aws_key_detected(tmp_path):
    write_tmp(tmp_path, "config.py", """
        key = "AKIAIOSFODNN7EXAMPLE"
    """)
    result = scan(str(tmp_path))
    assert not result.clean
    assert any(f.rule_id == "AWS_ACCESS_KEY" for f in result.findings)


def test_stripe_key_detected(tmp_path):
    secret = "sk_t" + "est_XXXXXXXXXXXXXXXXXXXXXXXX"
    write_tmp(tmp_path, "payments.js", f"""
        const stripe = require('stripe')('{secret}');
    """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "STRIPE_SECRET_KEY" for f in result.findings)


def test_github_token_detected(tmp_path):
    token = "gh" + "p_EXAMPLETOKEN36CHARSXXXXXXXXXXXXXXXXX"
    write_tmp(tmp_path, "ci.py", f"""
        token = "{token}"
    """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "GITHUB_TOKEN" for f in result.findings)


def test_database_url_detected(tmp_path):
    write_tmp(tmp_path, "settings.py", """
        DATABASE_URL = "postgres://admin:supersecret@db.example.com:5432/prod"
    """)
    result = scan(str(tmp_path))
    assert any(f.rule_id == "DATABASE_URL" for f in result.findings)


def test_clean_file(tmp_path):
    write_tmp(tmp_path, "hello.py", """
        print("hello world")
        x = 42
    """)
    result = scan(str(tmp_path))
    assert result.clean


# ── Entropy detection ────────────────────────────────────────── #

def test_high_entropy_flagged():
    # Simulate a 40-char base64-like string
    hits = high_entropy_strings('secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    assert len(hits) > 0


def test_low_entropy_ignored():
    hits = high_entropy_strings('message = "hello world this is normal text"')
    assert len(hits) == 0


# ── Ignore rules ─────────────────────────────────────────────── #

def test_ignored_file_skipped(tmp_path):
    (tmp_path / ".sourceguardignore").write_text("secrets_fixture.py\n")
    write_tmp(tmp_path, "secrets_fixture.py", """
        key = "AKIAIOSFODNN7EXAMPLE"
    """)
    result = scan(str(tmp_path))
    assert result.clean
    assert result.files_skipped >= 1


# ── Exit code behaviour (via severity filter) ─────────────────── #

def test_severity_filter(tmp_path):
    write_tmp(tmp_path, "app.py", """
        api_key = "some_api_key_value_here_1234567"
    """)
    result = scan(str(tmp_path))
    # Filter to only CRITICAL — MEDIUM generic key should disappear
    result.findings = [f for f in result.findings if f.severity == "CRITICAL"]
    assert result.clean
