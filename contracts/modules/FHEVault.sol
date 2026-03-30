// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <0.9.0;

import {Initializable}           from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable}         from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {euint128, Impl, Common} from "cofhe-contracts/FHE.sol";
import {ITaskManager} from "cofhe-contracts/ICofhe.sol";
import {ZMailTypes}              from "../libraries/ZMailTypes.sol";

/// @title  FHEVault
/// @notice Manages encrypted message payloads using Inco Network's coFHE SDK.
///
///         When a message is sent:
///           1. The client FHE-encrypts the body + subject off-chain using the
///              recipient's public key (stored in IdentityManager).
///           2. The ciphertext bytes are submitted here and stored as-is.
///           3. To read, the client calls `requestDecrypt`, which triggers the
///              Inco threshold network to re-encrypt the ciphertext under the
///              caller's session key (returned off-chain via event).
///
///         This means the smart contract NEVER sees plaintext.
///
/// @dev    Storage namespace: keccak256("zmail.storage.FHEVault") - 1
contract FHEVault is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable
{
    // ─────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:zmail.storage.FHEVault
    struct VaultStorage {
        // mailId => euint128 encrypted payload
        mapping(uint256 => euint128) ciphertexts;
        // mailId => ciphertext hash (for decryption)
        mapping(uint256 => uint256) ctHashes;
        // mailId => raw ciphertext bytes (optional, for backup)
        mapping(uint256 => bytes) rawCiphertexts;
        // owner => FHE public key (optional, for routing)
        mapping(address => bytes) publicKeys;
        // requestId => mailId (for tracking decrypt callbacks)
        mapping(uint256 => uint256) decryptRequests;
        bool initialized;
    }

    bytes32 private constant VAULT_STORAGE_SLOT =
        0xb5163505e48e6613026efc404bf3b737a29e9ebeb79ca8f1a5d7c35852f6a385; // ^ keccak256("zmail.storage.FHEVault") - 1  (computed off-chain, stored as constant)

    function _vaultStorage() private pure returns (VaultStorage storage vs) {
        assembly { vs.slot := VAULT_STORAGE_SLOT }
    }

    address private constant TASK_MANAGER_ADDRESS = 0xeA30c4B8b44078Bbf8a6ef5b9f1eC1626C7848D9;
    ITaskManager private constant taskManager = ITaskManager(TASK_MANAGER_ADDRESS);

    // ─────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────

    bytes32 public constant DOMAIN_ROLE = keccak256("DOMAIN_ROLE");
    bytes32 public constant ADMIN_ROLE  = keccak256("ADMIN_ROLE");

    // ─────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────

    event CiphertextStored(uint256 indexed mailId);
    event DecryptRequested(uint256 indexed mailId, uint256 indexed requestId, address indexed requester);
    event PublicKeyRegistered(address indexed owner, uint256 keyLength);

    // ─────────────────────────────────────────────────────────────
    // Custom Errors
    // ─────────────────────────────────────────────────────────────
    error ZeroAddress();
    error Unauthorized();
    error InvalidFHEKey();
    error NoCiphertext();
    error UpgradeNotAuthorized();

    // ─────────────────────────────────────────────────────────────
    // Initializer
    // ─────────────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        // __UUPSUpgradeable_init();
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _vaultStorage().initialized = true;
    }

    // ─────────────────────────────────────────────────────────────
    // Core – called by EmailDomain contracts
    // ─────────────────────────────────────────────────────────────

    /// @notice Store an encrypted message payload (as euint128)
    /// @param mailId Unique mail ID
    /// @param ciphertext Encrypted payload (euint128)
    /// @param ctHash Ciphertext hash (uint256)
    function storeCiphertext(uint256 mailId, euint128 ciphertext, uint256 ctHash)
        external
        onlyRole(DOMAIN_ROLE)
    {
        VaultStorage storage vs = _vaultStorage();
        vs.ciphertexts[mailId] = ciphertext;
        vs.ctHashes[mailId] = ctHash;
        emit CiphertextStored(mailId);
    }

    /// @notice Request decryption of a stored ciphertext
    /// @param mailId Unique mail ID
    function requestDecrypt(uint256 mailId) external {
        VaultStorage storage vs = _vaultStorage();
        uint256 ctHash = vs.ctHashes[mailId];
        if (ctHash == 0) revert NoCiphertext();
        taskManager.createDecryptTask(ctHash, msg.sender);
        // Use ctHash as the request identifier for tracking
        vs.decryptRequests[ctHash] = mailId;
        emit DecryptRequested(mailId, ctHash, msg.sender);
    }

    /// @notice Retrieve raw ciphertext (for backup or off-chain use)
    function getRawCiphertext(uint256 mailId) external view returns (bytes memory) {
        return _vaultStorage().rawCiphertexts[mailId];
    }

    /// @notice Get the encrypted payload for a mail
    function getCiphertext(uint256 mailId) external view returns (euint128) {
        return _vaultStorage().ciphertexts[mailId];
    }

    // ─────────────────────────────────────────────────────────────
    // Public key registry (optional)
    // ─────────────────────────────────────────────────────────────

    function registerPublicKey(address owner, bytes calldata pubkey)
        external
        onlyRole(DOMAIN_ROLE)
    {
        if (pubkey.length < 32) revert InvalidFHEKey();
        _vaultStorage().publicKeys[owner] = pubkey;
        emit PublicKeyRegistered(owner, pubkey.length);
    }

    function getPublicKey(address owner) external view returns (bytes memory) {
        return _vaultStorage().publicKeys[owner];
    }

    // ─────────────────────────────────────────────────────────────
    // Admin
    // ─────────────────────────────────────────────────────────────

    function grantDomainRole(address domain) external onlyRole(ADMIN_ROLE) {
        _grantRole(DOMAIN_ROLE, domain);
    }

    function revokeDomainRole(address domain) external onlyRole(ADMIN_ROLE) {
        _revokeRole(DOMAIN_ROLE, domain);
    }

    // ─────────────────────────────────────────────────────────────
    // UUPS
    // ─────────────────────────────────────────────────────────────

    function _authorizeUpgrade(address newImpl) internal override onlyRole(ADMIN_ROLE) {
        if (newImpl == address(0)) revert UpgradeNotAuthorized();
    }
}