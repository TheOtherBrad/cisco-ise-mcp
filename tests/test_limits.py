"""Resource governance: env ceilings, limiter behaviour, DC query shaping, upgrade path."""

import asyncio

import pytest

from cisco_ise_mcp import catalog, limits
from cisco_ise_mcp.dataconnect.client import (
    RawQueryRejected, resolve_days_back, validate_raw_select,
)


@pytest.fixture(autouse=True)
def _fresh_limiters():
    limits.reset_for_tests()
    yield
    limits.reset_for_tests()


@pytest.fixture
def dc_policy():
    return limits.resolve_policy("dataconnect", "test")


@pytest.fixture
def guard_args():
    views = catalog.get_dc_views(include_internal=True)
    return {
        "allowed_views": {v["view"].upper() for v in views.values()},
        "fact_views": catalog.get_fact_view_names(),
        "view_time_cols": {v["view"].upper(): v.get("time_col") for v in views.values()},
    }


def _guard(sql, guard_args, policy):
    return validate_raw_select(sql, guard_args["allowed_views"],
                               fact_views=guard_args["fact_views"],
                               view_time_cols=guard_args["view_time_cols"],
                               policy=policy)


# ── Policy resolution: env is a ceiling, the registry may only tighten ──

def test_defaults_match_documented_values(dc_policy):
    assert dc_policy.max_concurrent == 5
    assert dc_policy.acquire_wait_s == 5.0
    assert dc_policy.query_timeout_s == 60
    assert dc_policy.max_per_minute == 30
    assert dc_policy.default_days_back == 7
    assert dc_policy.max_days_back == 90
    assert dc_policy.default_row_limit == 500
    assert dc_policy.default_agg_row_limit == 5000
    assert dc_policy.max_fact_views == 3


def test_registry_may_tighten():
    p = limits.resolve_policy("dataconnect", "d", {"max_concurrent": 2})
    assert p.max_concurrent == 2
    assert "max_concurrent" in p.from_registry
    assert not p.clamped


def test_registry_may_not_raise_above_env_ceiling(monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_DC_MAX_CONCURRENT", "4")
    p = limits.resolve_policy("dataconnect", "d", {"max_concurrent": 50})
    assert p.max_concurrent == 4               # clamped down to the ceiling
    assert "max_concurrent" in p.clamped


def test_env_ceiling_applies_without_registry(monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_ERS_MAX_CONCURRENT", "3")
    assert limits.resolve_policy("ers", "d").max_concurrent == 3


def test_bad_env_value_falls_back(monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_DC_MAX_CONCURRENT", "not-a-number")
    assert limits.resolve_policy("dataconnect", "d").max_concurrent == 5


def test_zero_concurrency_cannot_deadlock():
    assert limits.resolve_policy("ers", "d", {"max_concurrent": 0}).max_concurrent >= 1


def test_acquire_wait_is_bounded():
    p = limits.resolve_policy("ers", "d", {"acquire_wait_s": 900})
    assert p.acquire_wait_s <= 15.0


# ── Limiter: admits up to N, refuses the rest with guidance ──

def test_concurrency_refuses_past_cap():
    async def go():
        lim = limits.SurfaceLimiter(
            limits.resolve_policy("ers", "d", {"max_concurrent": 1, "acquire_wait_s": 1}))
        async with lim.slot():
            with pytest.raises(limits.LimitExceeded) as ei:
                async with lim.slot():
                    pass
        return ei.value.payload

    payload = asyncio.run(go())
    assert payload["error"] == "concurrency_limited"
    assert "remediation" in payload           # actionable, not a bare failure
    assert payload["limits"]["max_concurrent"] == 1


def test_rate_limit_refuses_when_exhausted():
    async def go():
        lim = limits.SurfaceLimiter(
            limits.resolve_policy("dataconnect", "d", {"max_per_minute": 1}))
        async with lim.slot():
            pass
        with pytest.raises(limits.LimitExceeded) as ei:
            async with lim.slot():
                pass
        return ei.value.payload

    payload = asyncio.run(go())
    assert payload["error"] == "rate_limited"


def test_slot_released_after_error():
    async def go():
        lim = limits.SurfaceLimiter(limits.resolve_policy("ers", "d", {"max_concurrent": 1}))
        with pytest.raises(RuntimeError):
            async with lim.slot():
                raise RuntimeError("boom")
        async with lim.slot():          # must not deadlock
            pass
        return lim.in_flight

    assert asyncio.run(go()) == 0


def test_limiter_survives_a_new_event_loop():
    # asyncio.Semaphore binds to a loop; a cached limiter must not leak across runs.
    async def once():
        async with limits.get_limiter("d", "ers").slot():
            return True

    assert asyncio.run(once())
    assert asyncio.run(once())


# ── days_back: default injected, oversize clamped (not rejected) ──

def test_days_back_default_injected(dc_policy):
    assert resolve_days_back({}, "TIMESTAMP", dc_policy) == (7, "default")


def test_days_back_explicit_honoured(dc_policy):
    assert resolve_days_back({"days_back": 30}, "TIMESTAMP", dc_policy) == (30, "explicit")


def test_days_back_over_max_is_clamped_not_rejected(dc_policy):
    # A 120-day request must succeed as 90 rather than raise.
    assert resolve_days_back({"days_back": 120}, "TIMESTAMP", dc_policy) == (90, "clamped")


def test_views_without_time_column_are_exempt(dc_policy):
    assert resolve_days_back({"days_back": 120}, None, dc_policy) == (None, "n/a")


def test_days_back_garbage_falls_back_to_default(dc_policy):
    assert resolve_days_back({"days_back": "abc"}, "TIMESTAMP", dc_policy) == (7, "default")


# ── Raw SQL: row bounds injected, unsafe shapes rejected ──

def test_row_bound_injected_when_absent(guard_args, dc_policy):
    out = _guard('SELECT name FROM network_devices', guard_args, dc_policy)
    assert out.endswith("FETCH FIRST 500 ROWS ONLY")


def test_aggregate_gets_larger_bound(guard_args, dc_policy):
    out = _guard('SELECT COUNT(*) FROM network_devices', guard_args, dc_policy)
    assert out.endswith("FETCH FIRST 5000 ROWS ONLY")


def test_explicit_row_bound_is_untouched(guard_args, dc_policy):
    sql = 'SELECT name FROM network_devices FETCH FIRST 10 ROWS ONLY'
    assert _guard(sql, guard_args, dc_policy) == sql


def test_trailing_semicolon_stripped_before_appending(guard_args, dc_policy):
    out = _guard('SELECT name FROM network_devices;', guard_args, dc_policy)
    assert out.endswith("FETCH FIRST 500 ROWS ONLY")
    assert ";" not in out


def test_fact_view_needs_a_time_predicate(guard_args, dc_policy):
    with pytest.raises(RawQueryRejected) as ei:
        _guard("SELECT username FROM radius_authentications WHERE username='bob'",
               guard_args, dc_policy)
    assert ei.value.rule == "time-predicate"
    assert ei.value.example                      # refusal shows how to fix it


def test_time_bounded_fact_view_passes(guard_args, dc_policy):
    out = _guard('SELECT username FROM radius_authentications '
                 'WHERE "TIMESTAMP" >= SYSTIMESTAMP - NUMTODSINTERVAL(7,\'DAY\')',
                 guard_args, dc_policy)
    assert "FETCH FIRST 500 ROWS ONLY" in out


def test_one_fact_plus_many_dimensions_is_allowed(guard_args, dc_policy):
    # Guards against over-restriction: small lookup views join without limit.
    sql = ('SELECT ra.username, nd.name FROM radius_authentications ra '
           'JOIN network_devices nd ON nd.ip_mask = ra.nas_ip_address '
           'JOIN security_groups sg ON sg.name = ra.security_group '
           'JOIN failure_code_cause fc ON fc.cause = ra.failure_reason '
           'WHERE ra."TIMESTAMP" > SYSDATE-7')
    assert _guard(sql, guard_args, dc_policy).endswith("FETCH FIRST 500 ROWS ONLY")


def test_join_without_condition_is_rejected(guard_args, dc_policy):
    with pytest.raises(RawQueryRejected) as ei:
        _guard('SELECT * FROM radius_authentications ra JOIN network_devices nd '
               'WHERE ra."TIMESTAMP" > SYSDATE-7', guard_args, dc_policy)
    assert ei.value.rule == "join-condition"


def test_cross_join_is_rejected(guard_args, dc_policy):
    with pytest.raises(RawQueryRejected):
        _guard('SELECT * FROM radius_authentications ra CROSS JOIN network_devices nd '
               'WHERE ra."TIMESTAMP" > SYSDATE-7', guard_args, dc_policy)


def test_too_many_fact_views_rejected(guard_args, dc_policy):
    sql = ('SELECT 1 FROM radius_authentications a '
           'JOIN radius_accounting b ON a.id=b.id '
           'JOIN tacacs_accounting c ON c.id=a.id '
           'JOIN threat_events d ON d.id=a.id WHERE a."TIMESTAMP" > SYSDATE-1')
    with pytest.raises(RawQueryRejected) as ei:
        _guard(sql, guard_args, dc_policy)
    assert ei.value.rule == "fact-view-limit"


# ── CTEs: newly permitted, same guards ──

def test_cte_is_accepted(guard_args, dc_policy):
    sql = ('WITH recent AS (SELECT username FROM radius_authentications '
           'WHERE "TIMESTAMP" > SYSDATE-7) SELECT * FROM recent')
    assert _guard(sql, guard_args, dc_policy).endswith("FETCH FIRST 500 ROWS ONLY")


def test_cte_name_is_not_treated_as_a_catalog_view(guard_args, dc_policy):
    sql = ('WITH recent AS (SELECT username FROM radius_authentications '
           'WHERE "TIMESTAMP" > SYSDATE-7) SELECT * FROM recent')
    _guard(sql, guard_args, dc_policy)          # must not raise "not allowed: RECENT"


def test_cte_body_still_allow_listed(guard_args, dc_policy):
    with pytest.raises(ValueError, match="restricted to Data Connect catalog views"):
        _guard('WITH x AS (SELECT * FROM dba_users) SELECT * FROM x', guard_args, dc_policy)


# ── Structural guards must survive unchanged (regression) ──

def test_stacked_statements_still_rejected(guard_args, dc_policy):
    with pytest.raises(ValueError):
        _guard('SELECT 1 FROM DUAL; DROP TABLE x', guard_args, dc_policy)


def test_sql_comments_still_rejected(guard_args, dc_policy):
    with pytest.raises(ValueError):
        _guard('SELECT 1 FROM DUAL -- hide', guard_args, dc_policy)


def test_guards_are_opt_in_via_policy(guard_args):
    # Without a policy the structural checks still run but cost rules do not,
    # so pre-existing callers keep working.
    assert validate_raw_select('SELECT * FROM radius_authentications',
                               guard_args["allowed_views"]) is not None


# ── Curated fact list must not rot against a refreshed catalog ──

def test_every_fact_view_exists_in_catalog():
    assert catalog.unknown_fact_views() == []


# ── Upgrade path: a registry with no limits block still works ──

def test_registry_without_limits_block_loads_and_gets_defaults(cfg, monkeypatch):
    cfg.add_deployment(name="Legacy", host="1.1.1.1", ers_username="a")
    reg = cfg.load_registry()
    assert "limits" not in reg["deployments"]["legacy"]      # nothing written
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: "pw")
    resolved = cfg.get_deployment_config("legacy")
    assert resolved["limits"] == {}                          # sparse
    assert limits.resolve_policy("dataconnect", "legacy").max_concurrent == 5


def test_limits_can_be_set_and_tightened_via_registry(cfg):
    cfg.add_deployment(name="Prod", host="1.1.1.1", ers_username="a", dc_max_concurrent=2)
    assert cfg.load_registry()["deployments"]["prod"]["limits"]["dataconnect"]["max_concurrent"] == 2
    cfg.update_deployment("prod", ers_max_concurrent=4)
    block = cfg.load_registry()["deployments"]["prod"]["limits"]
    assert block["ers"]["max_concurrent"] == 4
    assert block["dataconnect"]["max_concurrent"] == 2       # patch, not replace


def test_invalid_limit_value_is_rejected(cfg):
    with pytest.raises(cfg.ConfigError):
        cfg.add_deployment(name="Bad", host="1.1.1.1", ers_username="a", dc_max_concurrent="lots")


def test_validate_reports_effective_limits(cfg, monkeypatch):
    cfg.add_deployment(name="Prod", host="1.1.1.1", ers_username="a", dataconnect_enabled=False)
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: "pw")
    result = cfg.validate_deployment("prod")
    assert result["limits"]["dataconnect"]["default_days_back"] == 7
    assert result["limits"]["ers"]["max_concurrent"] == 10
