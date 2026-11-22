"""Recovery workflow."""

from pathlib import Path

from backup_tool import restore_backup as restore_backup_impl


def restore_backup(
    archive: Path,
    destination: Path,
    custodian_a_share: Path,
    custodian_b_share: Path,
) -> dict[str, object]:
    return restore_backup_impl(
        archive,
        destination,
        custodian_a_share,
        custodian_b_share,
    )
