// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ResqdCanaryAnchor.sol";

contract ResqdCanaryAnchorTest is Test {
    ResqdCanaryAnchor public anchor;

    address owner = address(0xA11CE);
    address signer = address(0xB0B);
    address stranger = address(0xBADBAD);

    bytes32 constant ASSET_ID = keccak256("asset-001");
    bytes32 constant COMMIT_0 = keccak256("commitment-0");
    bytes32 constant COMMIT_1 = keccak256("commitment-1");
    bytes32 constant COMMIT_2 = keccak256("commitment-2");

    function setUp() public {
        vm.prank(owner);
        anchor = new ResqdCanaryAnchor();
        vm.prank(owner);
        anchor.authorizeSigner(signer);
    }

    // ---------------------------------------------------------------
    //                      CONSTRUCTOR & AUTH
    // ---------------------------------------------------------------

    function test_owner_is_deployer() public view {
        assertEq(anchor.owner(), owner);
    }

    function test_deployer_is_authorized_signer() public view {
        assertTrue(anchor.authorizedSigners(owner));
    }

    function test_owner_can_authorize_signer() public {
        address newSigner = address(0xC0FFEE);
        vm.prank(owner);
        anchor.authorizeSigner(newSigner);
        assertTrue(anchor.authorizedSigners(newSigner));
    }

    function test_owner_can_revoke_signer() public {
        vm.prank(owner);
        anchor.revokeSigner(signer);
        assertFalse(anchor.authorizedSigners(signer));
    }

    function test_stranger_cannot_authorize_signer() public {
        vm.prank(stranger);
        vm.expectRevert(ResqdCanaryAnchor.NotOwner.selector);
        anchor.authorizeSigner(stranger);
    }

    // ---------------------------------------------------------------
    //                          FIRST ANCHOR
    // ---------------------------------------------------------------

    function test_first_anchor_succeeds() public {
        vm.prank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));

        (bytes32 h, uint64 seq, uint64 ts, bool exists) = anchor.getAnchor(ASSET_ID);
        assertEq(h, COMMIT_0);
        assertEq(seq, 0);
        assertEq(ts, uint64(block.timestamp));
        assertTrue(exists);
    }

    function test_first_anchor_nonzero_sequence_reverts() public {
        vm.prank(signer);
        vm.expectRevert(
            abi.encodeWithSelector(ResqdCanaryAnchor.InvalidSequence.selector, 0, 5)
        );
        anchor.anchor(ASSET_ID, COMMIT_0, 5, bytes32(0));
    }

    function test_first_anchor_nonzero_prevhash_reverts() public {
        vm.prank(signer);
        vm.expectRevert(ResqdCanaryAnchor.FirstAnchorMustBeZero.selector);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, COMMIT_1);
    }

    function test_unauthorized_cannot_anchor() public {
        vm.prank(stranger);
        vm.expectRevert(ResqdCanaryAnchor.NotAuthorizedSigner.selector);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
    }

    // ---------------------------------------------------------------
    //                      CHAIN INTEGRITY
    // ---------------------------------------------------------------

    function test_chain_rotation_succeeds() public {
        vm.startPrank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
        anchor.anchor(ASSET_ID, COMMIT_1, 1, COMMIT_0);
        anchor.anchor(ASSET_ID, COMMIT_2, 2, COMMIT_1);
        vm.stopPrank();

        (bytes32 h, uint64 seq,, bool exists) = anchor.getAnchor(ASSET_ID);
        assertEq(h, COMMIT_2);
        assertEq(seq, 2);
        assertTrue(exists);
    }

    function test_skipped_sequence_reverts() public {
        vm.startPrank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(ResqdCanaryAnchor.InvalidSequence.selector, 1, 2)
        );
        anchor.anchor(ASSET_ID, COMMIT_1, 2, COMMIT_0);
        vm.stopPrank();
    }

    function test_replay_same_sequence_reverts() public {
        vm.startPrank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(ResqdCanaryAnchor.InvalidSequence.selector, 1, 0)
        );
        anchor.anchor(ASSET_ID, COMMIT_1, 0, bytes32(0));
        vm.stopPrank();
    }

    function test_wrong_prevhash_reverts() public {
        vm.startPrank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(
                ResqdCanaryAnchor.PrevHashMismatch.selector,
                COMMIT_0,
                COMMIT_2
            )
        );
        // Claim prev was COMMIT_2 but it's actually COMMIT_0
        anchor.anchor(ASSET_ID, COMMIT_1, 1, COMMIT_2);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------
    //                         VERIFICATION
    // ---------------------------------------------------------------

    function test_verify_access_count_never_anchored() public view {
        assertTrue(anchor.verifyAccessCount(ASSET_ID, 0));
        assertFalse(anchor.verifyAccessCount(ASSET_ID, 1));
    }

    function test_verify_access_count_after_rotations() public {
        vm.startPrank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
        anchor.anchor(ASSET_ID, COMMIT_1, 1, COMMIT_0);
        anchor.anchor(ASSET_ID, COMMIT_2, 2, COMMIT_1);
        vm.stopPrank();

        assertTrue(anchor.verifyAccessCount(ASSET_ID, 3));
        assertFalse(anchor.verifyAccessCount(ASSET_ID, 2));
        assertFalse(anchor.verifyAccessCount(ASSET_ID, 4));
    }

    function test_verify_current_commitment() public {
        vm.prank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));

        assertTrue(anchor.verifyCurrentCommitment(ASSET_ID, COMMIT_0));
        assertFalse(anchor.verifyCurrentCommitment(ASSET_ID, COMMIT_1));
    }

    // ---------------------------------------------------------------
    //                             EVENTS
    // ---------------------------------------------------------------

    function test_anchor_emits_event() public {
        vm.expectEmit(true, false, false, true);
        emit ResqdCanaryAnchor.CanaryAnchored(
            ASSET_ID,
            COMMIT_0,
            0,
            uint64(block.timestamp),
            bytes32(0)
        );
        vm.prank(signer);
        anchor.anchor(ASSET_ID, COMMIT_0, 0, bytes32(0));
    }

    // ---------------------------------------------------------------
    //                           FUZZING
    // ---------------------------------------------------------------

    function testFuzz_chain_of_length(uint8 length) public {
        length = uint8(bound(length, 1, 50)); // Keep gas reasonable
        bytes32 prevHash = bytes32(0);

        vm.startPrank(signer);
        for (uint64 i = 0; i < length; i++) {
            bytes32 commit = keccak256(abi.encodePacked("commit", i));
            anchor.anchor(ASSET_ID, commit, i, prevHash);
            prevHash = commit;
        }
        vm.stopPrank();

        (, uint64 seq,, bool exists) = anchor.getAnchor(ASSET_ID);
        assertTrue(exists);
        assertEq(seq, uint64(length) - 1);
        assertTrue(anchor.verifyAccessCount(ASSET_ID, uint64(length)));
    }
}
