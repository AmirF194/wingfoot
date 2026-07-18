"""Packaging invariants."""
import importlib.resources as resources


def test_py_typed_marker_is_shipped():
    """wingfoot is fully type-hinted; the PEP 561 marker must ship so that
    downstream type checkers actually read those hints."""
    marker = resources.files("wingfoot").joinpath("py.typed")
    assert marker.is_file()
