// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Initializable}           from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable}         from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ZMailTypes}              from "../libraries/ZMailTypes.sol";
import {MerkleLib}               from "../libraries/MerkleLib.sol";

/// @title  AttachmentRegistry
/// @notice Manages attachment metadata for ZMail.
///
///         Attachment storage flow:
///           1. Client encrypts file with a random symmetric key (AES-256-GCM).
///           2. Client uploads encrypted bytes to IPFS / Arweave (via Pinata / Lighthouse).
///           3. Client FHE-encrypts the symmetric key using the recipient's public key.
///           4. Client calls `registerAttachments` here, supplying CIDs + encrypted keys.
///           5. The Merkle root of all attachment descriptors is stored in MailEnvelope.
///
///         This means the contract never handles plaintext files — only CID pointers
///         and FHE-encrypted symmetric keys.
///
/// @dev    Storage namespace: keccak256("zmail.storage.AttachmentRegistry") - 1

abstract contract AttachmentRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable
{
    using MerkleLib for bytes32[];

    // ─────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:zmail.storage.AttachmentRegistry
    struct RegistryStorage {
        // mailId => array of attachment descriptors
        mapping(uint256 => ZMailTypes.Attachment[]) attachments;
        // mailId => cached Merkle root (computed at registration)
        mapping(uint256 => bytes32) roots;
        // cid => owner (prevents re-registration by different party)
        mapping(bytes32 => address) cidOwners;
        // domain contract => trusted flag
        mapping(address => bool) trustedDomains;
    }

    bytes32 private constant REGISTRY_STORAGE_SLOT =
        0x1abaed107bbdf55d52df4e1f2fcb8943acbaa7cb3975649988e4e53e9e2210d4; // ^ keccak256("zmail.storage.AttachmentRegistry") - 1  (computed off-chain, stored as constant)
    
    function _registryStorage() private pure returns (RegistryStorage storage rs) {
        assembly {
            rs.slot := REGISTRY_STORAGE_SLOT
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────

    bytes32 public constant DOMAIN_ROLE = keccak256("DOMAIN_ROLE"); // can register attachments for a domain's mail
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE"); // can manage trusted domains and upgrade

    // ─────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────

    event AttachmentsRegistered(uint256 indexed mailId, uint256 count, bytes32 root);

    // ─────────────────────────────────────────────────────────────
    // Custom Errors
    // ─────────────────────────────────────────────────────────────

    error AttachmentRegistry__InvalidCID();
    error AttachmentRegistry__InvalidEncryptedKey();
    error AttachmentRegistry__TooManyAttachments();
    error AttachmentRegistry__Unauthorized();

    // ─────────────────────────────────────────────────────────────
    // Initializer
    // ─────────────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {  _disableInitializers(); }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZMailTypes.ZMail__ZeroAddress();
        // __UUPSUpgradeable_init();
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    // ─────────────────────────────────────────────────────────────
    // Registration  (called by EmailDomain during sendMail)
    // ─────────────────────────────────────────────────────────────

    /// @notice Batch-register attachment descriptors for a mail.
    ///         Builds and stores the Merkle root on-chain.
    ///
    /// @param  mailId         The domain-scoped mail ID.
    /// @param  uploader       Original sender (msg.sender is the domain contract).
    /// @param  cids           Array of keccak256(raw CID string) — max 10.
    /// @param  encryptedKeys  FHE-encrypted symmetric keys per attachment.
    /// @param  sizes          File sizes in bytes per attachment.
    /// @param  mimeTypes      MIME type strings per attachment.
    /// @return root           Merkle root of the attachment set.
    function registerAttachments(
        uint256 mailId,
        address uploader,
        bytes32[] calldata cids,
        bytes[] calldata encryptedKeys,
        uint64[] calldata sizes,
        string[] calldata mimeTypes
    ) external returns (bytes32 root) {
        RegistryStorage storage rs = _registryStorage();
        if (!rs.trustedDomains[msg.sender]) revert AttachmentRegistry__Unauthorized();

        uint256 count = cids.length;
        if (count == 0  || count > ZMailTypes.MAX_ATTACHMENTS_PER_MAIL) {
            revert AttachmentRegistry__TooManyAttachments();
        }

        // All arrays must be parallel
        if (encryptedKeys.length != count || sizes.length != count || mimeTypes.length != count) {
            revert AttachmentRegistry__InvalidCID();
        }

        bytes32[] memory leaves = new bytes32[](count);

        for (uint256 i; i < count;) {
            if (cids[i] == bytes32(0)) revert AttachmentRegistry__InvalidCID();
            if (encryptedKeys[i].length == 0) revert AttachmentRegistry__InvalidEncryptedKey();

            // Prevent a different sender from re-registering the same CID
            if (rs.cidOwners[cids[i]] == address(0)) {
                rs.cidOwners[cids[i]] = uploader;
            }

            ZMailTypes.Attachment memory att = ZMailTypes.Attachment({
                cid: cids[i],
                encryptedKey: encryptedKeys[i],
                sizeBytes: sizes[i],
                mimeType: mimeTypes[i]
            });
            rs.attachments[mailId].push(att);

            leaves[i] = MerkleLib.leafHash(cids[i], sizes[i], keccak256(encryptedKeys[i]));
            unchecked { ++i; }
        }

        // Build Merkle root (pair-hash, sorted)
        root = _buildRoot(leaves);
        rs.roots[mailId] = root;

        emit AttachmentsRegistered(mailId, count, root);
        emit ZMailTypes.AttachmentRegistered(cids[0], uploader, mailId); // indexed event for easy lookup of attachments by CID
    }

    // ─────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────

    function getAttachments(uint256 mailId) external view returns (ZMailTypes.Attachment[] memory) {
        return _registryStorage().attachments[mailId];
    }

    function getRoot(uint256 mailId) external view returns (bytes32) {
        return _registryStorage().roots[mailId];
    }

    /// @notice Verify a single attachment is in the stored root.
    function verifyAttachment(
        uint256 mailId,
        bytes32 cid,
        uint64 sizeBytes,
        bytes32 encKeyHash,
        bytes32[] calldata proof
    ) external view returns (bool) {
        bytes32 leaf = MerkleLib.leafHash(cid, sizeBytes, encKeyHash);
        return MerkleLib.verify(proof, _registryStorage().roots[mailId], leaf);
    }

    // ─────────────────────────────────────────────────────────────
    // Admin
    // ─────────────────────────────────────────────────────────────
    
    function setTrustedDomain(address domain, bool trusted) external onlyRole(ADMIN_ROLE) {
        if (domain == address(0)) revert ZMailTypes.ZMail__ZeroAddress();
        _registryStorage().trustedDomains[domain] = trusted;
    }

    function grantDomainRole(address domain) external onlyRole(ADMIN_ROLE) {
        _grantRole(DOMAIN_ROLE, domain);
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    function _buildRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        uint256 n = leaves.length;
        if (n == 1) return leaves[0];

        while (n > 1) {
            uint256 nextN = (n + 1) / 2;
            for (uint256 i; i < nextN;) {
                uint256 left =  i * 2;
                uint256 right = left + 1 < n ? left + 1 : left;
                bytes32 l = leaves[left];
                bytes32 r = leaves[right];
                // Sort pair for determinism
                leaves[i] = l <= r
                    ? keccak256(abi.encodePacked(l, r))
                    : keccak256(abi.encodePacked(r, l));
                unchecked { ++i; }
            }

            n = nextN;
        }
        return leaves[0];
    }

    // ─────────────────────────────────────────────────────────────
    // UUPS
    // ─────────────────────────────────────────────────────────────

    function _authorizeUpgrade(address newImpl) internal view override onlyRole(ADMIN_ROLE) {
        if (newImpl == address(0)) revert ZMailTypes.ZMail__UpgradeNotAuthorized();
    }
}
