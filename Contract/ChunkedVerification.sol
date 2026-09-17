// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ChunkedVerification
 * @notice On-chain anchor for files stored as encrypted, independently
 *         verifiable chunks.
 *
 * What lives on-chain is deliberately tiny: for each document, the hash of the
 * plaintext, the Merkle root committing to every chunk, and the location of its
 * manifest. No file bytes are ever written to the chain.
 *
 * The Merkle root is what makes this more than a timestamp. Because the root
 * commits to every individual chunk, `verifyChunk` can prove that one specific
 * 256 KiB block belongs to a registered document without anyone downloading,
 * decrypting or revealing the rest of the file. A storage provider can be
 * challenged on a single block; a court can be shown that one page of a
 * document is authentic without disclosing the others.
 *
 * Hashing must match the off-chain implementation in js/core/chunker.js:
 *   leaf(chunk)        = sha256(0x00 || chunk)
 *   node(left, right)  = sha256(0x01 || left || right)
 *   a level with an odd node count promotes its last node unchanged.
 * The 0x00/0x01 domain separation prevents a chunk hash from being replayed as
 * an internal node (the second-preimage attack on naive Merkle trees).
 */
contract ChunkedVerification {
    struct Document {
        uint64 blockNumber;   // 0 means "no record"
        uint64 timestamp;
        uint32 totalChunks;
        uint64 fileSize;
        bool encrypted;
        address exporter;     // who registered it; only they may revoke
        bytes32 merkleRoot;   // commits to every chunk
        string manifestCID;   // where the manifest lives (e.g. an IPFS CID)
        string info;          // the exporter's label at registration time
    }

    struct Exporter {
        uint64 blockNumber;   // 0 means "not authorised"
        string info;
    }

    address public owner;
    address public pendingOwner;
    uint256 public exporterCount;
    uint256 public documentCount;

    mapping(bytes32 => Document) private _documents;
    mapping(address => Exporter) private _exporters;

    event ExporterAdded(address indexed exporter, string info);
    event ExporterUpdated(address indexed exporter, string info);
    event ExporterRemoved(address indexed exporter);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);
    event DocumentRegistered(
        address indexed exporter,
        bytes32 indexed fileHash,
        bytes32 merkleRoot,
        string manifestCID,
        uint32 totalChunks,
        uint64 fileSize,
        bool encrypted
    );
    event DocumentRevoked(address indexed exporter, bytes32 indexed fileHash);

    error NotOwner();
    error NotPendingOwner();
    error NotAuthorisedExporter();
    error NotDocumentOwner();
    error ZeroAddress();
    error AlreadyExists();
    error DoesNotExist();
    error InvalidArgument(string reason);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @dev Authorised exporters are the only accounts that may register documents.
    modifier onlyExporter() {
        if (_exporters[msg.sender].blockNumber == 0) revert NotAuthorisedExporter();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ---------------------------------------------------------------- ownership

    /// @notice Two-step handover: a typo in `newOwner` cannot brick the contract.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address previous = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, owner);
    }

    // ---------------------------------------------------------------- exporters

    function addExporter(address account, string calldata info) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (_exporters[account].blockNumber != 0) revert AlreadyExists();

        _exporters[account] = Exporter({blockNumber: uint64(block.number), info: info});
        unchecked {
            ++exporterCount;
        }
        emit ExporterAdded(account, info);
    }

    function updateExporter(address account, string calldata info) external onlyOwner {
        if (_exporters[account].blockNumber == 0) revert DoesNotExist();
        _exporters[account].info = info;
        emit ExporterUpdated(account, info);
    }

    function removeExporter(address account) external onlyOwner {
        if (_exporters[account].blockNumber == 0) revert DoesNotExist();
        delete _exporters[account];
        unchecked {
            --exporterCount;
        }
        emit ExporterRemoved(account);
    }

    function getExporter(address account) external view returns (uint64, string memory) {
        Exporter storage e = _exporters[account];
        return (e.blockNumber, e.info);
    }

    function isExporter(address account) external view returns (bool) {
        return _exporters[account].blockNumber != 0;
    }

    // ---------------------------------------------------------------- documents

    /**
     * @notice Anchor a chunked file.
     * @param fileHash    SHA-256 of the plaintext file — the lookup key.
     * @param merkleRoot  root of the Merkle tree over the plaintext chunk hashes.
     * @param manifestCID where the manifest is stored.
     * @param totalChunks number of chunks the file was split into.
     * @param fileSize    plaintext size in bytes.
     * @param encrypted   whether the stored chunks are encrypted.
     */
    function registerDocument(
        bytes32 fileHash,
        bytes32 merkleRoot,
        string calldata manifestCID,
        uint32 totalChunks,
        uint64 fileSize,
        bool encrypted
    ) external onlyExporter {
        if (fileHash == bytes32(0)) revert InvalidArgument("fileHash is zero");
        if (merkleRoot == bytes32(0)) revert InvalidArgument("merkleRoot is zero");
        if (totalChunks == 0) revert InvalidArgument("totalChunks is zero");
        if (bytes(manifestCID).length == 0) revert InvalidArgument("manifestCID is empty");
        if (_documents[fileHash].blockNumber != 0) revert AlreadyExists();

        _documents[fileHash] = Document({
            blockNumber: uint64(block.number),
            timestamp: uint64(block.timestamp),
            totalChunks: totalChunks,
            fileSize: fileSize,
            encrypted: encrypted,
            exporter: msg.sender,
            merkleRoot: merkleRoot,
            manifestCID: manifestCID,
            info: _exporters[msg.sender].info
        });
        unchecked {
            ++documentCount;
        }

        emit DocumentRegistered(
            msg.sender,
            fileHash,
            merkleRoot,
            manifestCID,
            totalChunks,
            fileSize,
            encrypted
        );
    }

    /**
     * @notice Revoke a record.
     * @dev Only the account that registered the document may revoke it. The
     *      original contract compared exporter *info strings*, which let any
     *      exporter sharing a label delete another's record.
     *
     *      Revocation clears the on-chain record; it cannot claw back bytes
     *      already stored off-chain. The event is the durable audit trail.
     */
    function revokeDocument(bytes32 fileHash) external {
        Document storage doc = _documents[fileHash];
        if (doc.blockNumber == 0) revert DoesNotExist();
        if (doc.exporter != msg.sender) revert NotDocumentOwner();

        delete _documents[fileHash];
        unchecked {
            --documentCount;
        }
        emit DocumentRevoked(msg.sender, fileHash);
    }

    function findDocument(bytes32 fileHash)
        external
        view
        returns (
            uint64 blockNumber,
            uint64 timestamp,
            bytes32 merkleRoot,
            string memory manifestCID,
            uint32 totalChunks,
            uint64 fileSize,
            bool encrypted,
            address exporter,
            string memory info
        )
    {
        Document storage doc = _documents[fileHash];
        return (
            doc.blockNumber,
            doc.timestamp,
            doc.merkleRoot,
            doc.manifestCID,
            doc.totalChunks,
            doc.fileSize,
            doc.encrypted,
            doc.exporter,
            doc.info
        );
    }

    function isRegistered(bytes32 fileHash) external view returns (bool) {
        return _documents[fileHash].blockNumber != 0;
    }

    // ------------------------------------------------------------ chunk proofs

    /**
     * @notice Prove that one chunk belongs to a registered document.
     * @param fileHash        the registered document.
     * @param chunkHash       leaf hash of the chunk: sha256(0x00 || chunk).
     * @param proof           sibling hashes from the leaf up to the root.
     * @param siblingOnRight  for each step, true if the sibling is the right node.
     *
     * Verifying one chunk costs a handful of sha256 precompile calls regardless
     * of file size — proving a block of a 10 GB file is as cheap as a 1 MB one.
     */
    function verifyChunk(
        bytes32 fileHash,
        bytes32 chunkHash,
        bytes32[] calldata proof,
        bool[] calldata siblingOnRight
    ) external view returns (bool) {
        if (proof.length != siblingOnRight.length) {
            revert InvalidArgument("proof and sides length mismatch");
        }
        Document storage doc = _documents[fileHash];
        if (doc.blockNumber == 0) revert DoesNotExist();

        return computeRoot(chunkHash, proof, siblingOnRight) == doc.merkleRoot;
    }

    /// @notice Recompute a Merkle root from a leaf and its sibling path.
    function computeRoot(
        bytes32 leaf,
        bytes32[] calldata proof,
        bool[] calldata siblingOnRight
    ) public pure returns (bytes32) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; ++i) {
            computed = siblingOnRight[i]
                ? sha256(abi.encodePacked(bytes1(0x01), computed, proof[i]))
                : sha256(abi.encodePacked(bytes1(0x01), proof[i], computed));
        }
        return computed;
    }

    /// @notice Leaf hash for a raw chunk, matching js/core/chunker.js.
    function leafHash(bytes calldata chunk) external pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x00), chunk));
    }
}
