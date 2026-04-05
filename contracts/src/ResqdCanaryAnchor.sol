// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ResqdCanaryAnchor
/// @notice Tamper-evident canary commitment anchor for the RESQD vault.
/// @dev Each asset has a chain of canary commitments. Every access to the
///      asset rotates the canary and produces a new commitment which MUST be
///      anchored on-chain before the access is considered valid. The contract
///      enforces chain integrity (monotonic sequence + prevHash linkage), so
///      no one — not even the RESQD service operator — can access an asset
///      without producing a verifiable on-chain trail.
///
/// @dev Design notes:
///      - assetId is the BLAKE3 hash of the client-side asset identifier,
///        preventing correlation of on-chain activity to account identities.
///      - commitmentHash is the BLAKE3 commitment produced in the Rust core
///        (canary_token || asset_id || sequence).
///      - Only authorized signers (typically the RESQD service's AWS KMS
///        signer address) may anchor. This is not a trust assumption — if the
///        signer misbehaves, the owner simply sees an unexpected on-chain
///        event for their asset and knows the vault was accessed without
///        their consent. That IS the tamper detection.
///      - There is no global pause or upgrade path. By design. "No one can
///        stop you from proving tampering" is a core product promise.
contract ResqdCanaryAnchor {
    // -------------------------------------------------------------------
    //                              TYPES
    // -------------------------------------------------------------------

    struct Anchor {
        bytes32 commitmentHash; // BLAKE3(token || asset_id || sequence)
        uint64 sequence;        // Monotonic, starts at 0
        uint64 timestamp;       // block.timestamp at anchor time
        bool exists;            // Distinguishes "never anchored" from "sequence 0"
    }

    // -------------------------------------------------------------------
    //                              STATE
    // -------------------------------------------------------------------

    address public immutable owner;
    mapping(address => bool) public authorizedSigners;
    mapping(bytes32 => Anchor) private _anchors;

    // -------------------------------------------------------------------
    //                              EVENTS
    // -------------------------------------------------------------------

    event CanaryAnchored(
        bytes32 indexed assetId,
        bytes32 commitmentHash,
        uint64 sequence,
        uint64 timestamp,
        bytes32 prevHash
    );
    event SignerAuthorized(address indexed signer);
    event SignerRevoked(address indexed signer);

    // -------------------------------------------------------------------
    //                              ERRORS
    // -------------------------------------------------------------------

    error NotOwner();
    error NotAuthorizedSigner();
    error InvalidSequence(uint64 expected, uint64 provided);
    error PrevHashMismatch(bytes32 expected, bytes32 provided);
    error FirstAnchorMustBeZero();

    // -------------------------------------------------------------------
    //                          CONSTRUCTOR
    // -------------------------------------------------------------------

    constructor() {
        owner = msg.sender;
        authorizedSigners[msg.sender] = true;
        emit SignerAuthorized(msg.sender);
    }

    // -------------------------------------------------------------------
    //                          MODIFIERS
    // -------------------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlySigner() {
        if (!authorizedSigners[msg.sender]) revert NotAuthorizedSigner();
        _;
    }

    // -------------------------------------------------------------------
    //                          ADMIN
    // -------------------------------------------------------------------

    function authorizeSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = true;
        emit SignerAuthorized(signer);
    }

    function revokeSigner(address signer) external onlyOwner {
        authorizedSigners[signer] = false;
        emit SignerRevoked(signer);
    }

    // -------------------------------------------------------------------
    //                          ANCHORING
    // -------------------------------------------------------------------

    /// @notice Anchor a canary commitment for an asset.
    /// @param assetId The opaque asset identifier (BLAKE3 hash).
    /// @param commitmentHash The new canary commitment.
    /// @param sequence The sequence number of this commitment.
    /// @param prevHash The previous commitment's hash (must equal current
    ///        stored hash). For the first anchor (sequence 0), pass bytes32(0).
    function anchor(
        bytes32 assetId,
        bytes32 commitmentHash,
        uint64 sequence,
        bytes32 prevHash
    ) external onlySigner {
        Anchor storage current = _anchors[assetId];

        if (!current.exists) {
            // First anchor for this asset
            if (sequence != 0) revert InvalidSequence(0, sequence);
            if (prevHash != bytes32(0)) revert FirstAnchorMustBeZero();
        } else {
            // Subsequent anchor — enforce chain integrity
            uint64 expectedSeq = current.sequence + 1;
            if (sequence != expectedSeq) {
                revert InvalidSequence(expectedSeq, sequence);
            }
            if (prevHash != current.commitmentHash) {
                revert PrevHashMismatch(current.commitmentHash, prevHash);
            }
        }

        current.commitmentHash = commitmentHash;
        current.sequence = sequence;
        current.timestamp = uint64(block.timestamp);
        current.exists = true;

        emit CanaryAnchored(
            assetId,
            commitmentHash,
            sequence,
            uint64(block.timestamp),
            prevHash
        );
    }

    // -------------------------------------------------------------------
    //                          VIEWS
    // -------------------------------------------------------------------

    /// @notice Get the current anchor state for an asset.
    /// @return commitmentHash Current commitment hash.
    /// @return sequence Current sequence (== total access count - 1).
    /// @return timestamp Unix timestamp of last anchor.
    /// @return exists True if the asset has ever been anchored.
    function getAnchor(bytes32 assetId)
        external
        view
        returns (
            bytes32 commitmentHash,
            uint64 sequence,
            uint64 timestamp,
            bool exists
        )
    {
        Anchor storage a = _anchors[assetId];
        return (a.commitmentHash, a.sequence, a.timestamp, a.exists);
    }

    /// @notice Verify that an asset has exactly the expected access count.
    /// @dev Returns true iff the asset exists AND its sequence + 1 == expected.
    ///      (sequence is 0-indexed; access count == sequence + 1.)
    function verifyAccessCount(bytes32 assetId, uint64 expectedCount)
        external
        view
        returns (bool)
    {
        Anchor storage a = _anchors[assetId];
        if (!a.exists) return expectedCount == 0;
        return uint64(a.sequence) + 1 == expectedCount;
    }

    /// @notice Verify that an asset's current commitment matches.
    function verifyCurrentCommitment(bytes32 assetId, bytes32 expectedHash)
        external
        view
        returns (bool)
    {
        return _anchors[assetId].commitmentHash == expectedHash;
    }
}
