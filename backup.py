"""Backup workflow."""

from pathlib import Path

from backup_tool import create_backup_material


def create_backup(
    source: Path,
    archive: Path,
    custodian_a: tuple[str, bytes],
    custodian_b: tuple[str, bytes],
) -> dict[str, object]:
    return create_backup_material(source, archive, custodian_a, custodian_b)
