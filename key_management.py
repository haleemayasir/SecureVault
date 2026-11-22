"""Recovery-share generation and reconstruction."""

from backup_tool import join_key, split_key


def create_recovery_shares(key: bytes) -> tuple[bytes, bytes]:
    return split_key(key)


def reconstruct_key(share_a: bytes, share_b: bytes) -> bytes:
    return join_key(share_a, share_b)
