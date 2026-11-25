"""Pair authenticated-open trials on synthetic archives across epoch retirement."""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ieee_joint_recovery import Gateway, canonical, digest


@dataclass(frozen=True)
class Trial:
    retained_slot_authenticated_open: bool
    retired_slot_absent: bool
    retired_slot_authenticated_open: bool
    archive_unchanged: bool
    regranted_epoch_authenticated_open: bool
    old_slot_absent_after_regrant: bool


def write_archive(path, gateway, operation):
    record = gateway.issued[operation]
    path.write_bytes(canonical({
        "binding": record.binding,
        "handle": record.handle,
        "nonce": record.nonce.hex(),
        "sealed": record.sealed.hex(),
    }))


def open_with_active_index(path, gateway):
    archive = json.loads(path.read_bytes())
    _, scope, epoch, _, expected_digest = archive["binding"]
    with gateway.locks.read(scope):
        key = gateway.keys.get((scope, epoch))
        if key is None:
            return "slot_absent"
        try:
            body = AESGCM(key).decrypt(
                bytes.fromhex(archive["nonce"]), bytes.fromhex(archive["sealed"]),
                canonical((*archive["binding"], archive["handle"])),
            ).decode()
        except InvalidTag:
            return "authentication_failed"
        if digest(body) != expected_digest:
            return "digest_mismatch"
        return "authenticated_open"


def run_trial(directory, number):
    scope, retired_epoch, new_epoch = "withdrawn", 1, 2
    operation = f"snapshot-control-{number}"
    archive = directory / f"{operation}.json"
    fresh = directory / f"{operation}-fresh.json"
    gateway = Gateway(receiver=None)
    gateway.grant(scope, retired_epoch)
    gateway.issue(operation, scope, retired_epoch, "normal", "snapshot_control")
    write_archive(archive, gateway, operation)
    before = hashlib.sha256(archive.read_bytes()).digest()
    retained = open_with_active_index(archive, gateway)
    gateway.revoke(retired_epoch)
    published = gateway.events[-1]
    assert published["event"] == "revoke_published" and published["epoch"] == retired_epoch
    retired = open_with_active_index(archive, gateway)

    new_operation = f"{operation}-fresh"
    gateway.grant(scope, new_epoch)
    gateway.issue(new_operation, scope, new_epoch, "normal", "snapshot_control")
    write_archive(fresh, gateway, new_operation)
    return Trial(
        retained_slot_authenticated_open=retained == "authenticated_open",
        retired_slot_absent=retired == "slot_absent",
        retired_slot_authenticated_open=retired == "authenticated_open",
        archive_unchanged=hashlib.sha256(archive.read_bytes()).digest() == before,
        regranted_epoch_authenticated_open=open_with_active_index(fresh, gateway) == "authenticated_open",
        old_slot_absent_after_regrant=open_with_active_index(archive, gateway) == "slot_absent",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pairs", type=int, default=60)
    args = parser.parse_args()
    if args.pairs < 1:
        parser.error("pairs must be positive")

    with tempfile.TemporaryDirectory(prefix="ieee-snapshot-seal-") as temporary:
        archive_directory = Path(temporary)
        rows = [asdict(run_trial(archive_directory, i)) for i in range(1, args.pairs + 1)]
    counts = {name: sum(row[name] for row in rows) for name in rows[0]}
    expected = {name: args.pairs for name in counts}
    expected["retired_slot_authenticated_open"] = 0
    result = {
        "pairs": args.pairs,
        "description": "The same keyless persisted synthetic archive is loaded before and after Gateway.revoke.",
        "key_lookup": "Only the current Gateway index is consulted. No detached key copies are used.",
        "outcome": "An authenticated open also has to reproduce the bound plaintext digest.",
        "limits": "This control covers the active index. Physical erasure, external caches, backup recovery, and keys acquired before retirement are untested.",
        "counts": counts,
        "per_pair": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as report:
        json.dump(result, report, indent=2)
        report.write("\n")
    print(json.dumps(counts))
    if counts != expected:
        raise SystemExit("The snapshot control did not meet its expected outcomes.")


if __name__ == "__main__":
    main()
