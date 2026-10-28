import json
import hashlib
import time
import uuid
from pathlib import Path

from web3 import Web3
from web3.exceptions import TransactionNotFound

from ..config import settings
from ..models import Batch
from .merkle_service import inclusion_proof, merkle_root, verify_inclusion

DEPLOYMENT_FILE = Path(__file__).resolve().parents[1] / "contract_deployment.json"


class BlockchainUnavailable(RuntimeError):
    pass


def provider() -> Web3:
    w3 = Web3(Web3.HTTPProvider(settings.blockchain_rpc_url, request_kwargs={"timeout": 3}))
    try:
        if not w3.is_connected():
            raise BlockchainUnavailable("Local EVM RPC is unavailable")
    except BlockchainUnavailable:
        raise
    except Exception as exc:
        raise BlockchainUnavailable(f"Local EVM RPC is unavailable: {type(exc).__name__}") from None
    return w3


def load_contract(w3: Web3):
    if not DEPLOYMENT_FILE.exists():
        raise BlockchainUnavailable("EvidenceLedger contract has not been deployed to this chain")
    config = json.loads(DEPLOYMENT_FILE.read_text())
    if int(w3.eth.chain_id) != int(config["chainId"]):
        raise BlockchainUnavailable("Deployed contract chain ID differs from the connected EVM")
    address = Web3.to_checksum_address(config["address"])
    try:
        bytecode = w3.eth.get_code(address)
    except Exception as exc:
        raise BlockchainUnavailable(f"Could not inspect EvidenceLedger deployment: {type(exc).__name__}") from None
    if not bytecode:
        raise BlockchainUnavailable(
            f"No EvidenceLedger contract is deployed at {address} on chain {config['chainId']}. "
            "The local Hardhat chain may have been reset; deploy it with `npm run deploy:local` from contracts/."
        )
    return w3.eth.contract(address=address, abi=config["abi"]), config


def anchor_batch(batch: Batch) -> tuple[str, str, int]:
    w3 = provider()
    contract, config = load_contract(w3)
    accounts = w3.eth.accounts
    if not accounts:
        raise BlockchainUnavailable("Connected EVM has no unlocked development account")
    case_id = Web3.keccak(text=batch.case_id)
    batch_id = Web3.keccak(text=batch.id)
    tx_hash = contract.functions.anchorBatch(case_id, batch_id, bytes.fromhex(batch.merkle_root),
                                             bytes.fromhex(batch.manifest_commitment), batch.evidence_count).transact({"from": accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    if receipt.status != 1:
        raise BlockchainUnavailable("EVM rejected the batch anchoring transaction")
    return receipt.transactionHash.hex(), config["address"], int(w3.eth.chain_id)


def anchor_audit(through_sequence: int, commitment: str) -> tuple[str, str, int]:
    w3 = provider()
    contract, config = load_contract(w3)
    accounts = w3.eth.accounts
    if not accounts:
        raise BlockchainUnavailable("Connected EVM has no unlocked development account")
    tx_hash = contract.functions.anchorAuditLog(through_sequence, bytes.fromhex(commitment)).transact({"from": accounts[0]})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    if receipt.status != 1:
        raise BlockchainUnavailable("EVM rejected the audit log commitment transaction")
    return receipt.transactionHash.hex(), config["address"], int(w3.eth.chain_id)


def read_audit_commitment(through_sequence: int) -> dict:
    w3 = provider()
    contract, config = load_contract(w3)
    value = contract.functions.auditCommitments(through_sequence).call()
    commitment = bytes(value).hex()
    return {"anchored": commitment != "0" * 64, "commitment": commitment if commitment != "0" * 64 else None,
            "chain_id": int(w3.eth.chain_id), "contract_address": config["address"]}


def transaction_details(tx_hash: str) -> dict:
    w3 = provider()
    contract, config = load_contract(w3)
    try:
        tx = w3.eth.get_transaction(tx_hash)
    except TransactionNotFound:
        return {"found": False, "status": "NOT_FOUND", "chain_id": int(w3.eth.chain_id),
                "reason": "This transaction hash is not present on the connected chain. A local Hardhat reset or redeploy can make previously recorded transaction hashes unavailable; the saved ForenSeal batch remains available for re-anchoring."}
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except TransactionNotFound:
        receipt = None
    events = []
    if receipt is not None:
        for raw_log in receipt.logs:
            for name in ("BatchRootAnchored", "EvidenceHashAnchored", "CustodyEventRecorded", "AuditLogAnchored"):
                try:
                    event = getattr(contract.events, name)().process_log(raw_log)
                    args = {key: (value.hex() if isinstance(value, bytes) else int(value) if hasattr(value, "__int__") and not isinstance(value, str) else value)
                            for key, value in event["args"].items()}
                    events.append({"event": name, "args": args})
                    break
                except Exception:
                    continue
    return {"found": True, "status": "PENDING" if receipt is None else "SUCCESS" if receipt.status == 1 else "FAILED",
            "transaction_hash": tx["hash"].hex(), "chain_id": int(w3.eth.chain_id), "network": config["network"],
            "contract_address": config["address"], "from": tx["from"], "to": tx["to"],
            "block_number": int(receipt.blockNumber) if receipt else None,
            "gas_limit": int(tx["gas"]), "gas_used": int(receipt.gasUsed) if receipt else None,
            "effective_gas_price_wei": int(receipt.effectiveGasPrice) if receipt and hasattr(receipt, "effectiveGasPrice") else None,
            "events": events}


def record_custody_event(evidence_id: str, event_type: str, actor_wallet: str | None,
                         recipient_wallet: str | None, reason: str) -> tuple[str, int | None, int]:
    w3 = provider()
    contract, _config = load_contract(w3)
    accounts = [Web3.to_checksum_address(a) for a in w3.eth.accounts]
    actor = Web3.to_checksum_address(actor_wallet) if actor_wallet else (accounts[0] if accounts else None)
    if actor is None or actor not in accounts:
        raise BlockchainUnavailable("Actor wallet is not an unlocked account on this local EVM")
    mapping = {"COLLECTION": 0, "ACCESS": 1, "VERIFICATION": 2, "TRANSFER_INITIATED": 3}
    if event_type not in mapping:
        raise ValueError("Unsupported on-chain custody event type")
    recipient = Web3.to_checksum_address(recipient_wallet) if recipient_wallet else "0x0000000000000000000000000000000000000000"
    if event_type == "TRANSFER_INITIATED" and recipient not in accounts:
        raise BlockchainUnavailable("Transfer recipient must be an unlocked Hardhat account for local acknowledgment")
    if event_type != "TRANSFER_INITIATED" and recipient_wallet:
        raise ValueError("Only transfer initiation may include a recipient")
    reason_hash = Web3.keccak(text=reason or "unspecified")
    tx = contract.functions.recordCustody(Web3.keccak(text=evidence_id), mapping[event_type], recipient, reason_hash).transact({"from": actor})
    receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
    if receipt.status != 1:
        raise BlockchainUnavailable("EVM rejected the custody event transaction")
    logs = contract.events.CustodyEventRecorded().process_receipt(receipt)
    args = logs[0]["args"] if logs else {}
    transfer_id = int(args.get("transferId", 0)) or None
    sequence = int(args.get("sequence", 0))
    return receipt.transactionHash.hex(), transfer_id, sequence


def resolve_custody_transfer(evidence_id: str, transfer_id: int, recipient_wallet: str,
                             accepted: bool, acknowledgment: str) -> str:
    w3 = provider()
    contract, _config = load_contract(w3)
    recipient = Web3.to_checksum_address(recipient_wallet)
    accounts = [Web3.to_checksum_address(a) for a in w3.eth.accounts]
    if recipient not in accounts:
        raise BlockchainUnavailable("Recipient wallet is not unlocked by this local EVM")
    acknowledgment_hash = Web3.keccak(text=acknowledgment)
    tx = contract.functions.resolveTransfer(Web3.keccak(text=evidence_id), transfer_id, accepted,
                                            acknowledgment_hash).transact({"from": recipient})
    receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
    if receipt.status != 1:
        raise BlockchainUnavailable("EVM rejected the transfer acknowledgment")
    return receipt.transactionHash.hex()


def authorize_wallet(wallet_address: str) -> str | None:
    w3 = provider()
    contract, _config = load_contract(w3)
    owner = Web3.to_checksum_address(w3.eth.accounts[0])
    wallet = Web3.to_checksum_address(wallet_address)
    if wallet == owner or contract.functions.authorized(wallet).call():
        return None
    tx = contract.functions.setAuthorized(wallet, True).transact({"from": owner})
    receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
    if receipt.status != 1:
        raise BlockchainUnavailable("EVM rejected wallet authorization")
    return receipt.transactionHash.hex()


def read_batch(batch: Batch) -> dict:
    w3 = provider()
    contract, config = load_contract(w3)
    try:
        record = contract.functions.getBatch(Web3.keccak(text=batch.id)).call()
    except Exception as exc:
        raise BlockchainUnavailable(
            f"Could not read this batch from the configured EvidenceLedger ({type(exc).__name__}); "
            "check that the deployment address and ABI match the connected Hardhat chain."
        ) from None
    onchain_root = bytes(record[1]).hex()
    anchored = int(record[3]) > 0
    return {"available": True, "anchored": anchored, "root": onchain_root if anchored else None,
            "case_id": bytes(record[0]).hex() if anchored else None,
            "manifest_commitment": bytes(record[2]).hex() if anchored else None,
            "chain_id": int(w3.eth.chain_id), "contract_address": config["address"]}


def status() -> dict:
    try:
        w3 = provider()
        contract, config = load_contract(w3)
        return {"connected": True, "chain_id": int(w3.eth.chain_id), "block_number": int(w3.eth.block_number),
                "contract_address": config["address"], "network": config["network"]}
    except (BlockchainUnavailable, OSError, ValueError) as exc:
        return {"connected": False, "reason": str(exc), "rpc_url": settings.blockchain_rpc_url}


def run_benchmark(size: int) -> dict:
    """Execute and measure real EVM transactions. No gas price valuation is inferred."""
    w3 = provider()
    contract, config = load_contract(w3)
    accounts = w3.eth.accounts
    if not accounts:
        raise BlockchainUnavailable("Connected EVM has no unlocked development account")
    account = accounts[0]
    run_id = str(uuid.uuid4())
    entries = [(str(uuid.uuid5(uuid.UUID(run_id), str(i))), hashlib.sha256(f"{run_id}:{i}".encode()).hexdigest()) for i in range(size)]
    build_start = time.perf_counter()
    root = merkle_root(entries)
    build_seconds = time.perf_counter() - build_start
    proof_start = time.perf_counter()
    for evidence_id, digest in entries:
        proof = inclusion_proof(entries, evidence_id)
        if not verify_inclusion(evidence_id, digest, proof, root):
            raise RuntimeError("Locally generated benchmark proof failed verification")
    verify_seconds = time.perf_counter() - proof_start

    individual_gas = 0
    individual_receipts = []
    individual_start = time.perf_counter()
    for evidence_id, digest in entries:
        tx = contract.functions.anchorEvidence(Web3.keccak(text=evidence_id), bytes.fromhex(digest)).transact({"from": account})
        receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
        if receipt.status != 1:
            raise BlockchainUnavailable("An individual evidence anchoring transaction failed")
        individual_gas += int(receipt.gasUsed)
        individual_receipts.append({"transaction_hash": receipt.transactionHash.hex(), "gas_used": int(receipt.gasUsed), "success": True})
    individual_seconds = time.perf_counter() - individual_start

    batch_id = Web3.keccak(text=f"benchmark:{run_id}")
    case_id = Web3.keccak(text=f"benchmark-case:{run_id}")
    manifest = hashlib.sha256("".join(f"{identifier}:{digest};" for identifier, digest in entries).encode()).digest()
    batch_start = time.perf_counter()
    tx = contract.functions.anchorBatch(case_id, batch_id, bytes.fromhex(root), manifest, size).transact({"from": account})
    receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=30)
    batch_seconds = time.perf_counter() - batch_start
    if receipt.status != 1:
        raise BlockchainUnavailable("The batch root transaction failed")
    return {"size": size, "run_id": run_id, "network": config["network"], "chain_id": int(w3.eth.chain_id),
            "contract_address": config["address"], "merkle_root": root, "transaction_count": size + 1,
            "individual": {"transactions": size, "total_gas": individual_gas,
                           "gas_per_evidence": individual_gas / size, "elapsed_seconds": individual_seconds,
                           "receipts": individual_receipts},
            "batched": {"transactions": 1, "total_gas": int(receipt.gasUsed),
                        "gas_per_evidence": int(receipt.gasUsed) / size, "elapsed_seconds": batch_seconds,
                        "transaction_hash": receipt.transactionHash.hex(), "success": True},
            "offchain_merkle_seconds": build_seconds, "verification_seconds": verify_seconds,
            "success": True, "gas_price_wei": None, "monetary_cost": None}
