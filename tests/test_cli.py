from __future__ import annotations

from agent_guard.cli import main


def test_allowed_command_runs(capsys):
    code = main(["run", "--dev-trust-runtime", "--", "echo", "hi"])
    assert code == 0
    assert "hi" in capsys.readouterr().out


def test_rm_rf_is_blocked():
    code = main(["run", "--dev-trust-runtime", "--", "rm", "-rf", "/tmp/x"])
    assert code == 3


def test_drop_table_is_blocked():
    code = main(["run", "--dev-trust-runtime", "--", "echo", "DROP TABLE users"])
    assert code == 3


def test_empty_command_errors():
    assert main(["run", "--dev-trust-runtime", "--"]) == 1


def test_untrusted_runtime_is_refused():
    code = main(["run", "--", "echo", "hi"])
    assert code == 2
