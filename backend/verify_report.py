"""Independently check a report's file fingerprint and/or local EVM Merkle root."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from web3 import Web3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, help="Evidence file to hash")
    parser.add_argument("--sha256", help="Ingestion SHA-256 from the report")
    parser.add_argument("--batch-id", help="Batch UUID from the report; requires a reachable local EVM")
    parser.add_argument("--merkle-root", help="Expected Merkle root from the report")
    parser.add_argument("--deployment", type=Path, default=Path("app/contract_deployment.json"))
    parser.add_argument("--rpc", default="http://127.0.0.1:8545")
    args = parser.parse_args()
    if not args.file and not args.batch_id:
        parser.error("provide --file or --batch-id")
    checks = []
    if args.file:
        if not args.sha256:
            parser.error("--file requires --sha256")
        digest = hashlib.sha256()
        with args.file.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        current = digest.hexdigest()
        checks.append({"check": "file_sha256", "expected": args.sha256.lower(), "actual": current,
                       "matches": current == args.sha256.lower()})
    if args.batch_id:
        if not args.merkle_root:
            parser.error("--batch-id requires --merkle-root")
        if not args.deployment.is_file():
            parser.error(f"deployment metadata not found: {args.deployment}")
        deployment = json.loads(args.deployment.read_text())
        w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 3}))
        if not w3.is_connected():
            parser.error("local EVM RPC is unavailable")
        if int(w3.eth.chain_id) != int(deployment["chainId"]):
            parser.error("connected EVM chain ID differs from deployment metadata")
        contract = w3.eth.contract(address=Web3.to_checksum_address(deployment["address"]), abi=deployment["abi"])
        record = contract.functions.getBatch(Web3.keccak(text=args.batch_id)).call()
        actual = bytes(record[1]).hex()
        checks.append({"check": "onchain_merkle_root", "expected": args.merkle_root.lower(), "actual": actual,
                       "anchored": int(record[3]) > 0, "matches": int(record[3]) > 0 and actual == args.merkle_root.lower(),
                       "chain_id": int(w3.eth.chain_id), "contract_address": deployment["address"]})
    print(json.dumps({"valid": all(check["matches"] for check in checks), "checks": checks}, indent=2))
    return 0 if all(check["matches"] for check in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
