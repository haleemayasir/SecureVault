"""Backup workflow."""

from pathlib import Path

from backup_tool import create_backup as create_backup_impl


def create_backup(
    source: Path,
    archive: Path,
    custodian_a_share: Path,
    custodian_b_share: Path,
) -> dict[str, object]:
    return create_backup_impl(
        source,
        archive,
        custodian_a_share,
        custodian_b_share,
    )
