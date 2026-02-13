"""Tests for atlas.planner.noise_budget — NoiseBudgetManager."""

from atlas.planner.noise_budget import NoiseBudgetManager


def test_initial_state():
    mgr = NoiseBudgetManager(total_budget=10.0)
    assert mgr.total == 10.0
    assert mgr.spent == 0.0
    assert mgr.remaining == 10.0
    assert mgr.utilization == 0.0
    assert not mgr.is_exhausted


def test_spend():
    mgr = NoiseBudgetManager(total_budget=5.0)
    result = mgr.spend("a1", "iam:ListUsers", 1.0)
    assert result is True
    assert mgr.spent == 1.0
    assert mgr.remaining == 4.0


def test_budget_exhaustion():
    mgr = NoiseBudgetManager(total_budget=2.0)
    mgr.spend("a1", "iam:CreateAccessKey", 1.5)
    result = mgr.spend("a2", "iam:AttachUserPolicy", 1.0)
    assert result is False  # 1.5 + 1.0 = 2.5 > 2.0
    assert mgr.is_exhausted


def test_can_afford():
    mgr = NoiseBudgetManager(total_budget=3.0)
    mgr.spend("a1", "x", 2.0)
    assert mgr.can_afford(0.5) is True
    assert mgr.can_afford(1.5) is False


def test_project_spend():
    mgr = NoiseBudgetManager(total_budget=5.0)
    mgr.spend("a1", "x", 1.0)
    projection = mgr.project_spend([1.0, 2.0, 3.0])
    assert projection["current_spent"] == 1.0
    assert projection["projected_total"] == 7.0
    assert projection["within_budget"] is False
    assert len(projection["steps"]) == 3


def test_ledger():
    mgr = NoiseBudgetManager(total_budget=10.0)
    mgr.spend("a1", "iam:ListUsers", 0.08)
    mgr.spend("a2", "iam:GetRole", 0.05)
    ledger = mgr.get_ledger()
    assert len(ledger) == 2
    assert ledger[0]["action_id"] == "a1"
    assert ledger[1]["cumulative"] > ledger[0]["cumulative"]
