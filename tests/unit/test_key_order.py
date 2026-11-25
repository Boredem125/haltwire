"""Gemini key order is chosen by env (ARENA_GEMINI_KEYS / ARENA_JUDGE_KEYS), names only."""
import pytest

from arena import agent, intent, runner


@pytest.fixture
def keys_env(monkeypatch, tmp_path):
    for n in ("GEMINI_API_KEY", "GEMINI_API_KEY1", "GEMINI_API_KEY2", "GEMINI_API_KEY3",
              "ARENA_GEMINI_KEYS", "ARENA_JUDGE_KEYS"):
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "k-main")
    monkeypatch.setenv("GEMINI_API_KEY1", "k-one")
    monkeypatch.setenv("GEMINI_API_KEY3", "k-three")
    # no arena/.env lookups leaking in: point the module at an empty dir
    monkeypatch.setattr(agent, "__file__", str(tmp_path / "agent.py"))
    return monkeypatch


def _order(client):
    return list(client._keys)


def test_default_order_unchanged(keys_env):
    assert agent._load_keys() == ["k-main", "k-one"]
    assert _order(intent._make_client()) == ["k-one", "k-main"]


def test_env_puts_key3_first_for_agent_and_judge(keys_env):
    keys_env.setenv("ARENA_GEMINI_KEYS", "GEMINI_API_KEY3,GEMINI_API_KEY,GEMINI_API_KEY1")
    keys_env.setenv("ARENA_JUDGE_KEYS", "GEMINI_API_KEY3,GEMINI_API_KEY1,GEMINI_API_KEY")
    assert agent._load_keys() == ["k-three", "k-main", "k-one"]
    assert _order(agent._make_client()) == ["k-three", "k-main", "k-one"]
    assert _order(intent._make_client()) == ["k-three", "k-one", "k-main"]


def test_judge_defaults_to_reverse_of_agent_order(keys_env):
    keys_env.setenv("ARENA_GEMINI_KEYS", "GEMINI_API_KEY3,GEMINI_API_KEY")
    assert _order(intent._make_client()) == ["k-main", "k-three"]


def test_missing_named_key_is_skipped(keys_env):
    keys_env.setenv("ARENA_GEMINI_KEYS", "GEMINI_API_KEY2,GEMINI_API_KEY")
    assert agent._load_keys() == ["k-main"]


@pytest.mark.parametrize("bad", ["ARENA_ADMIN_TOKEN", "BOLNA_API_KEY", "GEMINI_API_KEY_OLD", "PATH"])
def test_only_gemini_key_names_allowed(keys_env, bad):
    keys_env.setenv("ARENA_GEMINI_KEYS", f"GEMINI_API_KEY,{bad}")
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        agent._load_keys()


def test_numbered_gemini_keys_never_reach_agent_subprocess(keys_env):
    keys_env.setenv("GEMINI_API_KEY2", "k-two")
    env = runner.agent_env()
    assert not any(k.startswith("GEMINI_API_KEY") and v in ("k-two", "k-three", "k-one")
                   for k, v in env.items())
    assert "GEMINI_API_KEY3" not in env and "GEMINI_API_KEY2" not in env
