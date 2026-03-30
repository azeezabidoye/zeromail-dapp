// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title  MerkleLib
/// @notice Minimal Merkle-tree helper for attachment CID roots.
///         The client builds the tree off-chain (sorted pairs) and submits only the root.
///         Verification is optional (caller may supply a proof) but the root alone is stored
///         so gas is minimal for the happy path.
library MerkleLib {
    /// @notice Verify a Merkle proof.
    /// @param proof Ordered array of sibling hashes from leaf to root
    /// @param root Expected root.
    /// @param leaf keccak256 of the leaf data.
    function verify(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        uint256 len = proof.length;
        for (uint256 i; i < len; ) {
            bytes32 proofElement = proof[i];
            // Sort pair to match off-chain sorted-pair tree
            computed = computed <= proofElement
                ? keccak256(abi.encodePacked(computed, proofElement))
                : keccak256(abi.encodePacked(proofElement, computed));
            unchecked {
                ++i;
            }
        }
        return computed == root;
    }

    /// @notice Hash a single attachment descriptor into a leaf.
    function leafHash(
        bytes32 cid,
        uint64 sizeBytes,
        bytes32 encKeyHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(cid, sizeBytes, encKeyHash));
    }
}
