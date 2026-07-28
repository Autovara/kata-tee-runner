"""A pinned vector for the credential bundle binding, mirrored in every repo that computes it.

This value is an interface, not an implementation detail. A miner's sealing tool computes it on
their machine and seals a credential to the result; this room recomputes it from the extracted
bundle and refuses the credential if they differ. Any repository that must produce the digest -- a
subnet's own submission tooling, for instance -- carries this same vector, and the room's own tests
carry it too so a change here is caught here rather than in whoever mirrors it.

``room/bundle.py`` is the authoritative implementation. If a change to it is deliberate, this vector
must be regenerated *and* every mirror updated in the same breath. If a change trips this test
unexpectedly, that is the test doing its job: silently altering this digest invalidates every sealed
credential already submitted, and the symptom is "not bound to this candidate bundle" on submissions
that were fine yesterday.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from room.bundle import SEALED_CREDENTIAL_FILENAME, credential_bundle_binding

VECTOR_FILES = {
    "agent.py": b"def agent_main():\n    return {}\n",
    "submission.json": b'{"submission_id":"pinned"}\n',
    "helpers/util.py": b"VALUE = 1\n",
    # A dash-named sibling of the nested directory, on purpose: it is what makes the ordering rule
    # observable. See test_the_ordering_is_by_path_parts below.
    "helpers-extra.py": b"VALUE = 2\n",
    SEALED_CREDENTIAL_FILENAME: b"deadbeefcafe",
}
VECTOR_DIGEST = "e7b9e082a71716f3dab9157797fc476ef4312bc69aa2cb0ea93b66314e524ed5"


def _materialise(root: Path, files: dict) -> Path:
    bundle = root / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return bundle


def test_the_pinned_vector_still_holds(tmp_path: Path) -> None:
    """Changing this digest invalidates every credential already sealed against it."""
    assert credential_bundle_binding(_materialise(tmp_path, VECTOR_FILES)) == VECTOR_DIGEST


def test_the_ordering_is_by_path_parts(tmp_path: Path) -> None:
    """The walk sorts ``Path`` objects, so ordering is by path *parts*, not the joined string.

    ``helpers/util.py`` sorts before ``helpers-extra.py`` one way and after it the other. Any mirror
    that sorts relative paths as plain strings will disagree with this room on any bundle containing
    both -- which is an entirely ordinary bundle.
    """
    names = ["helpers/util.py", "helpers-extra.py"]
    as_paths = [str(path) for path in sorted(Path(name) for name in names)]
    assert as_paths == ["helpers/util.py", "helpers-extra.py"]
    assert sorted(names) != as_paths, "a plain string sort disagrees -- that is the whole point"


def test_the_ciphertext_is_excluded_from_its_own_binding(tmp_path: Path) -> None:
    changed = {**VECTOR_FILES, SEALED_CREDENTIAL_FILENAME: b"a-completely-different-ciphertext"}
    assert credential_bundle_binding(_materialise(tmp_path, changed)) == VECTOR_DIGEST


@pytest.mark.parametrize("changed", ["agent.py", "submission.json", "helpers/util.py"])
def test_editing_any_submitted_file_invalidates_the_binding(tmp_path: Path, changed: str) -> None:
    tampered = {**VECTOR_FILES, changed: b"tampered\n"}
    assert credential_bundle_binding(_materialise(tmp_path, tampered)) != VECTOR_DIGEST


def test_content_cannot_be_shifted_between_adjacent_files(tmp_path: Path) -> None:
    """Why the path and content lengths are prefixed rather than concatenated."""
    first = credential_bundle_binding(
        _materialise(tmp_path / "a", {"ab.py": b"", "c.py": b"x"})
    )
    second = credential_bundle_binding(
        _materialise(tmp_path / "b", {"a.py": b"", "bc.py": b"x"})
    )
    assert first != second
