// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract EvidenceLedger {
    enum EventType { Collection, Access, Verification, TransferInitiated, TransferAccepted, TransferRejected }

    struct BatchRecord {
        bytes32 caseId;
        bytes32 merkleRoot;
        bytes32 manifestCommitment;
        uint64 anchoredAt;
        address anchoredBy;
    }

    struct CustodyRecord {
        uint64 sequence;
        uint64 timestamp;
        EventType eventType;
        address actor;
        address recipient;
        bytes32 evidenceRef;
        bytes32 reasonHash;
        uint64 transferId;
    }

    address public administrator;
    mapping(address => bool) public authorized;
    mapping(bytes32 => BatchRecord) private batches;
    mapping(bytes32 => bytes32) private individualEvidence;
    mapping(uint64 => bytes32) public auditCommitments;
    mapping(bytes32 => CustodyRecord[]) private custody;
    mapping(uint64 => bool) public transferResolved;
    uint64 public nextSequence = 1;
    uint64 public nextTransferId = 1;

    event AuthorizedOperatorUpdated(address indexed operator, bool authorized);
    event BatchRootAnchored(bytes32 indexed caseId, bytes32 indexed batchId, bytes32 merkleRoot, bytes32 manifestCommitment, uint256 evidenceCount, address anchoredBy, uint256 timestamp);
    event EvidenceHashAnchored(bytes32 indexed evidenceRef, bytes32 sha256Hash, address anchoredBy, uint256 timestamp);
    event AuditLogAnchored(uint64 indexed throughSequence, bytes32 commitment, address anchoredBy, uint256 timestamp);
    event CustodyEventRecorded(bytes32 indexed evidenceRef, uint64 indexed sequence, EventType eventType, address actor, address recipient, bytes32 reasonHash, uint64 transferId, uint256 timestamp);

    modifier onlyAdmin() { require(msg.sender == administrator, "administrator only"); _; }
    modifier onlyAuthorized() { require(authorized[msg.sender], "operator not authorized"); _; }

    constructor() { administrator = msg.sender; authorized[msg.sender] = true; }

    function setAuthorized(address operator, bool enabled) external onlyAdmin {
        require(operator != address(0), "zero operator");
        authorized[operator] = enabled;
        emit AuthorizedOperatorUpdated(operator, enabled);
    }

    function anchorBatch(bytes32 caseId, bytes32 batchId, bytes32 root, bytes32 manifest, uint256 count) external onlyAuthorized {
        require(caseId != bytes32(0) && batchId != bytes32(0), "empty identifier");
        require(root != bytes32(0) && manifest != bytes32(0) && count > 0, "empty commitment");
        require(batches[batchId].anchoredAt == 0, "batch already anchored");
        batches[batchId] = BatchRecord(caseId, root, manifest, uint64(block.timestamp), msg.sender);
        emit BatchRootAnchored(caseId, batchId, root, manifest, count, msg.sender, block.timestamp);
    }

    function getBatch(bytes32 batchId) external view returns (BatchRecord memory) { return batches[batchId]; }

    function anchorEvidence(bytes32 evidenceRef, bytes32 sha256Hash) external onlyAuthorized {
        require(evidenceRef != bytes32(0) && sha256Hash != bytes32(0), "empty commitment");
        require(individualEvidence[evidenceRef] == bytes32(0), "evidence already anchored");
        individualEvidence[evidenceRef] = sha256Hash;
        emit EvidenceHashAnchored(evidenceRef, sha256Hash, msg.sender, block.timestamp);
    }

    function getEvidenceHash(bytes32 evidenceRef) external view returns (bytes32) { return individualEvidence[evidenceRef]; }

    function anchorAuditLog(uint64 throughSequence, bytes32 commitment) external onlyAuthorized {
        require(throughSequence > 0 && commitment != bytes32(0), "empty audit commitment");
        require(auditCommitments[throughSequence] == bytes32(0), "audit sequence already anchored");
        auditCommitments[throughSequence] = commitment;
        emit AuditLogAnchored(throughSequence, commitment, msg.sender, block.timestamp);
    }

    function recordCustody(bytes32 evidenceRef, EventType eventType, address recipient, bytes32 reasonHash) external onlyAuthorized returns (uint64 sequence, uint64 transferId) {
        require(evidenceRef != bytes32(0), "empty evidence reference");
        if (eventType == EventType.TransferInitiated) require(recipient != address(0) && recipient != msg.sender, "invalid recipient");
        else require(recipient == address(0), "recipient only for transfer");
        if (eventType == EventType.TransferAccepted || eventType == EventType.TransferRejected) revert("use resolveTransfer");
        sequence = nextSequence++;
        if (eventType == EventType.TransferInitiated) transferId = nextTransferId++;
        custody[evidenceRef].push(CustodyRecord(sequence, uint64(block.timestamp), eventType, msg.sender, recipient, evidenceRef, reasonHash, transferId));
        emit CustodyEventRecorded(evidenceRef, sequence, eventType, msg.sender, recipient, reasonHash, transferId, block.timestamp);
    }

    function resolveTransfer(bytes32 evidenceRef, uint64 transferId, bool accepted, bytes32 acknowledgmentHash) external returns (uint64 sequence) {
        require(evidenceRef != bytes32(0) && transferId != 0, "invalid transfer");
        require(!transferResolved[transferId], "transfer already resolved");
        address intended;
        CustodyRecord[] storage records = custody[evidenceRef];
        for (uint256 i = records.length; i > 0; i--) {
            if (records[i - 1].transferId == transferId && records[i - 1].eventType == EventType.TransferInitiated) { intended = records[i - 1].recipient; break; }
        }
        require(intended != address(0) && msg.sender == intended, "only intended recipient can acknowledge");
        require(acknowledgmentHash != bytes32(0), "acknowledgment required");
        transferResolved[transferId] = true;
        sequence = nextSequence++;
        EventType result = accepted ? EventType.TransferAccepted : EventType.TransferRejected;
        records.push(CustodyRecord(sequence, uint64(block.timestamp), result, msg.sender, address(0), evidenceRef, acknowledgmentHash, transferId));
        emit CustodyEventRecorded(evidenceRef, sequence, result, msg.sender, address(0), acknowledgmentHash, transferId, block.timestamp);
    }

    function custodyCount(bytes32 evidenceRef) external view returns (uint256) { return custody[evidenceRef].length; }
    function custodyAt(bytes32 evidenceRef, uint256 index) external view returns (CustodyRecord memory) { return custody[evidenceRef][index]; }
}
