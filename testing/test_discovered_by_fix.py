"""
Standalone verification for the discovered_by single-attribution fix.

Not a substitute for the project's real mocked-subprocess test suite
(tests/ isn't part of this session's checkout) or the real zonetransfer.me
run the project's staged-verification discipline calls for - this only
proves the state.py logic itself is correct in isolation, using sqlite3
directly (no other project files needed), before handing the fix back for
the real cycle.
"""
import json
import sqlite3
import tempfile
from pathlib import Path
import sys
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _p in (_HERE, *_HERE.parents):
    if (_p / "state.py").exists():
        _REPO_ROOT = _p; break
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "stages"))
from state import Asset, RunState


def fresh_state():
    tmpdir = tempfile.mkdtemp()
    return RunState(Path(tmpdir))


def test_same_batch_collision_merges_discovered_by():
    # mirrors the real amass/assetfinder zonetransfer.me collision:
    # assetfinder finds the bare host with no metadata, amass finds the
    # same host in the same stage-1 batch WITH metadata attached.
    state = fresh_state()
    a1 = Asset(value="zonetransfer.me", type="subdomain",
               discovered_by="assetfinder", discovered_at_stage=1, discovered_in_pass=1)
    a2 = Asset(value="zonetransfer.me", type="subdomain",
               discovered_by="amass", discovered_at_stage=1, discovered_in_pass=1,
               metadata={"mx_hosts": ["mail.zonetransfer.me"]})

    new = state.add_assets([a1, a2])
    assert len(new) == 1, f"expected 1 genuinely-new asset, got {len(new)}"

    loaded = state.load_assets()
    assert len(loaded) == 1
    row = loaded[0]
    assert set(row.discovered_by) == {"assetfinder", "amass"}, row.discovered_by
    assert row.metadata.get("mx_hosts") == ["mail.zonetransfer.me"], row.metadata
    print("PASS: same-batch collision merges discovered_by AND metadata")


def test_cross_call_rediscovery_merges_discovered_by_even_with_no_metadata():
    # a later stage/pass rediscovers an existing asset with a DIFFERENT
    # tool and NO new metadata at all - discovered_by must still gain the
    # new tool (this is the part a metadata-only merge would miss).
    state = fresh_state()
    first = Asset(value="www.zonetransfer.me", type="subdomain",
                  discovered_by="subfinder", discovered_at_stage=1, discovered_in_pass=1)
    state.add_assets([first])

    rediscovered = Asset(value="www.zonetransfer.me", type="subdomain",
                          discovered_by="puredns_permutations", discovered_at_stage=3,
                          discovered_in_pass=1)
    new = state.add_assets([rediscovered])
    assert len(new) == 0, "rediscovery of an existing (type, value) should not count as genuinely new"

    loaded = state.load_assets()
    assert len(loaded) == 1
    assert set(loaded[0].discovered_by) == {"subfinder", "puredns_permutations"}, loaded[0].discovered_by
    print("PASS: cross-call rediscovery with no new metadata still merges discovered_by")


def test_no_duplicate_tool_names_on_repeat_rediscovery():
    # the same tool rediscovering the same asset across multiple passes
    # shouldn't pile up duplicate entries in discovered_by.
    state = fresh_state()
    state.add_assets([Asset(value="a.zonetransfer.me", type="subdomain",
                             discovered_by="subfinder", discovered_at_stage=1, discovered_in_pass=1)])
    state.add_assets([Asset(value="a.zonetransfer.me", type="subdomain",
                             discovered_by="subfinder", discovered_at_stage=1, discovered_in_pass=2)])

    loaded = state.load_assets()
    assert loaded[0].discovered_by == ["subfinder"], loaded[0].discovered_by
    print("PASS: repeat rediscovery by the same tool does not duplicate its name")


def test_backward_compat_with_old_scalar_format():
    # simulate a pre-fix run directory: discovered_by column holds a bare
    # tool-name string, not a JSON list, because it was written by the
    # old code (or hand-crafted here to stand in for one).
    state = fresh_state()
    with state._connect() as conn:
        conn.execute(
            "INSERT INTO assets (asset_id, value, type, discovered_by, "
            "discovered_at_stage, discovered_in_pass, scope_status, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("old-asset-id", "legacy.zonetransfer.me", "subdomain", "assetfinder",
             1, 1, "in_scope", "{}"),
        )

    loaded = state.load_assets()
    assert len(loaded) == 1
    assert loaded[0].discovered_by == ["assetfinder"], loaded[0].discovered_by
    print("PASS: old pre-fix scalar discovered_by column loads cleanly, no migration needed")

    # and a rediscovery against that old-format row should upgrade it to
    # the new JSON-list format transparently
    new = state.add_assets([Asset(value="legacy.zonetransfer.me", type="subdomain",
                                   discovered_by="amass", discovered_at_stage=1,
                                   discovered_in_pass=2)])
    assert len(new) == 0
    loaded = state.load_assets()
    assert set(loaded[0].discovered_by) == {"assetfinder", "amass"}, loaded[0].discovered_by
    print("PASS: rediscovering an old-format row upgrades it to a merged JSON list")


def test_single_tool_asset_round_trips_as_list_of_one():
    # the overwhelmingly common case (no collision at all) still works,
    # and Asset construction with a bare str is unchanged for call sites.
    state = fresh_state()
    a = Asset(value="only.zonetransfer.me", type="subdomain",
              discovered_by="katana", discovered_at_stage=6, discovered_in_pass=1)
    assert a.discovered_by == ["katana"], a.discovered_by  # __post_init__ normalization

    state.add_assets([a])
    loaded = state.load_assets()
    assert loaded[0].discovered_by == ["katana"]
    print("PASS: plain single-tool construction and round-trip unaffected")


if __name__ == "__main__":
    test_same_batch_collision_merges_discovered_by()
    test_cross_call_rediscovery_merges_discovered_by_even_with_no_metadata()
    test_no_duplicate_tool_names_on_repeat_rediscovery()
    test_backward_compat_with_old_scalar_format()
    test_single_tool_asset_round_trips_as_list_of_one()
    print("\nAll checks passed.")