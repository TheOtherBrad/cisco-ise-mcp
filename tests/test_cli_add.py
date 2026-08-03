"""CLI `add`: guided TTY prompts (DC / cert / MAPI) and flag-only non-TTY path."""

import io

import pytest


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


class _Feeder:
    """Answer scripted prompts in order; fail loudly on an unexpected extra prompt."""

    def __init__(self, answers):
        self.answers = list(answers)

    def __call__(self, prompt=""):
        assert self.answers, f"unexpected prompt: {prompt!r}"
        return self.answers.pop(0)


def _run_add(cfg, monkeypatch, argv, answers, tty=True):
    from cisco_ise_mcp import cli
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: None)
    monkeypatch.setattr(cli.sys, "stdin", _FakeTTY() if tty else io.StringIO())
    feeder = _Feeder(answers)
    monkeypatch.setattr("builtins.input", feeder)
    rc = cli.main(argv)
    return rc, feeder


def test_guided_ca_os_trust_and_mapi_on(cfg, monkeypatch):
    rc, feeder = _run_add(
        cfg, monkeypatch,
        ["add", "--name", "CA Lab", "--host", "10.0.0.1", "--ers-username", "ers"],
        answers=["y",    # enable Data Connect?
                 "n",    # separate MnT node?
                 "ca",   # self-signed or CA-signed?
                 "os",   # OS store or file?
                 "y"],   # enable MAPI?
    )
    assert rc == 0 and feeder.answers == []
    dep = cfg.load_registry()["deployments"]["ca-lab"]
    assert dep["dataconnect"]["enabled"] is True
    assert dep["dataconnect"]["os_trust"] is True
    assert dep["dataconnect"]["cert_path"] == ""
    assert dep["monitoring_enabled"] is True


def test_guided_self_signed_separate_host_mapi_off(cfg, monkeypatch):
    rc, feeder = _run_add(
        cfg, monkeypatch,
        ["add", "--name", "Self Lab", "--host", "10.0.0.1", "--ers-username", "ers"],
        answers=["y",            # enable Data Connect?
                 "y",            # separate MnT node?
                 "10.9.9.9",     # MnT host
                 "self-signed",  # cert kind
                 "/opt/dc.pem",  # cert path
                 "n"],           # enable MAPI?
    )
    assert rc == 0 and feeder.answers == []
    dep = cfg.load_registry()["deployments"]["self-lab"]
    assert dep["dataconnect"]["host"] == "10.9.9.9"
    assert dep["dataconnect"]["cert_path"] == "/opt/dc.pem"
    assert dep["dataconnect"]["os_trust"] is False
    assert dep["monitoring_enabled"] is False


def test_guided_decline_dataconnect(cfg, monkeypatch):
    rc, feeder = _run_add(
        cfg, monkeypatch,
        ["add", "--name", "ERS Only", "--host", "10.0.0.1", "--ers-username", "ers"],
        answers=["n",   # enable Data Connect? -> no
                 "n"],  # enable MAPI? -> no
    )
    assert rc == 0 and feeder.answers == []
    dep = cfg.load_registry()["deployments"]["ers-only"]
    assert dep["dataconnect"]["enabled"] is False
    assert dep["monitoring_enabled"] is False


def test_non_tty_uses_flags_without_prompting(cfg, monkeypatch):
    # No TTY -> no prompts at all; flags drive os_trust + monitoring.
    rc, feeder = _run_add(
        cfg, monkeypatch,
        ["add", "--name", "Flagged", "--host", "1.2.3.4", "--ers-username", "x",
         "--dc-os-trust", "--enable-monitoring"],
        answers=[], tty=False,
    )
    assert rc == 0 and feeder.answers == []
    dep = cfg.load_registry()["deployments"]["flagged"]
    assert dep["dataconnect"]["os_trust"] is True
    assert dep["monitoring_enabled"] is True


def test_dc_flag_suppresses_dc_prompts(cfg, monkeypatch):
    # A DC detail flag (--dc-cert) skips the DC walk-through; only MAPI is asked.
    rc, feeder = _run_add(
        cfg, monkeypatch,
        ["add", "--name", "Flagged DC", "--host", "1.2.3.4", "--ers-username", "x",
         "--dc-cert", "/opt/x.pem"],
        answers=["n"],  # only the MAPI prompt remains
    )
    assert rc == 0 and feeder.answers == []
    dep = cfg.load_registry()["deployments"]["flagged-dc"]
    assert dep["dataconnect"]["cert_path"] == "/opt/x.pem"
    assert dep["monitoring_enabled"] is False
