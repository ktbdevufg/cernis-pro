"""Unit-Tests der process-Domaene -- reine Logik, kein I/O, keine Uhr.

Prueft die Kernel/Userland-Klassifikation (``classify_kind`` -- cmdline + PID-2-Lage)
und den Aufbau des Prozess-Walds (``build_process_tree`` -- Wurzel-Erkennung,
deterministische pid-Sortierung, Zyklen-/Selbstreferenz-Schutz). Alle Werte kommen als
Felder herein -> rein deterministisch.
"""

from domain.process import (
    ProcessInfo,
    ProcessNode,
    build_process_tree,
    classify_kind,
)


def _proc(
    pid: int,
    ppid: int | None = None,
    *,
    cmdline: tuple[str, ...] = ("/usr/bin/foo",),
) -> ProcessInfo:
    """Baut ein ProcessInfo mit sinnvollen Defaults fuer die Tests."""
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        name="foo",
        owner="kbach",
        status="sleeping",
        create_time=None,
        cmdline=cmdline,
    )


# ── classify_kind ────────────────────────────────────────────────────────────


def test_classify_kind_kernel_via_ppid() -> None:
    # leeres cmdline + ppid == 2 -> kernel
    assert classify_kind(_proc(123, ppid=2, cmdline=())) == "kernel"


def test_classify_kind_kernel_via_pid() -> None:
    # leeres cmdline + pid == 2 (kthreadd selbst) -> kernel
    assert classify_kind(_proc(2, ppid=0, cmdline=())) == "kernel"


def test_classify_kind_userland_with_cmdline() -> None:
    # nicht-leeres cmdline -> userland (auch wenn ppid == 2)
    assert classify_kind(_proc(123, ppid=2, cmdline=("/usr/bin/foo",))) == "userland"


def test_classify_kind_userland_empty_cmdline_but_not_pid2() -> None:
    # leeres cmdline, aber weder pid noch ppid == 2 -> userland
    assert classify_kind(_proc(123, ppid=456, cmdline=())) == "userland"


# ── build_process_tree ───────────────────────────────────────────────────────


def test_build_tree_simple_one_root_two_children() -> None:
    procs = [_proc(1, ppid=None), _proc(10, ppid=1), _proc(11, ppid=1)]
    forest = build_process_tree(procs)
    assert len(forest) == 1
    root = forest[0]
    assert root.info.pid == 1
    assert tuple(c.info.pid for c in root.children) == (10, 11)
    # Kinder sind Blaetter
    assert all(c.children == () for c in root.children)


def test_build_tree_forest_multiple_roots_sorted() -> None:
    # Zwei Wurzeln (beide ppid None), absichtlich in falscher Reihenfolge uebergeben.
    procs = [_proc(5, ppid=None), _proc(3, ppid=None), _proc(50, ppid=5)]
    forest = build_process_tree(procs)
    assert tuple(n.info.pid for n in forest) == (3, 5)
    # Die zweite Wurzel hat das Kind 50
    assert tuple(c.info.pid for c in forest[1].children) == (50,)


def test_build_tree_orphan_becomes_root() -> None:
    # ppid 999 existiert nicht in der Menge -> 42 wird selbst Wurzel.
    procs = [_proc(1, ppid=None), _proc(42, ppid=999)]
    forest = build_process_tree(procs)
    assert tuple(n.info.pid for n in forest) == (1, 42)
    assert all(n.children == () for n in forest)


def test_build_tree_deterministic_sorting() -> None:
    # Eingangsreihenfolge bewusst durcheinander; Wurzeln UND Kinder muessen
    # aufsteigend nach pid herauskommen.
    procs = [
        _proc(1, ppid=None),
        _proc(30, ppid=1),
        _proc(10, ppid=1),
        _proc(20, ppid=1),
    ]
    forest = build_process_tree(procs)
    assert tuple(n.info.pid for n in forest) == (1,)
    assert tuple(c.info.pid for c in forest[0].children) == (10, 20, 30)


def test_build_tree_self_reference_no_infinite_loop() -> None:
    # pid == ppid (Selbstreferenz) -> wird Wurzel, keine Endlosschleife.
    procs = [_proc(7, ppid=7)]
    forest = build_process_tree(procs)
    assert len(forest) == 1
    assert forest[0].info.pid == 7
    # Sich selbst NICHT als eigenes Kind einhaengen.
    assert forest[0].children == ()


def test_build_tree_returns_process_nodes() -> None:
    # Strukturtyp pruefen: der Wald besteht aus ProcessNode.
    forest = build_process_tree([_proc(1, ppid=None)])
    assert isinstance(forest[0], ProcessNode)


def test_build_tree_empty_input() -> None:
    assert build_process_tree([]) == ()
