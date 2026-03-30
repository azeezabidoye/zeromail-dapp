// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {EIP712Upgradeable}   from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ZMailTypes} from "../libraries/ZMailTypes.sol";

/// @title  GaslessRelayer
/// @notice EIP-2771 compliant trusted forwarder.  The frontend signs meta-transactions
///         using EIP-712 typed-data; this contract verifies the signature, replays nonce
///         protection, then calls the target domain contract on behalf of the signer.
///
///         Gas is paid by Anthropic / protocol treasury — users pay zero ETH.
///
/// @dev    Storage layout (EIP-7201 namespace):
///         keccak256("zmail.storage.GaslessRelayer") - 1
contract GaslessRelayer is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    EIP712Upgradeable
{
    using ECDSA for bytes32;

    // ─────────────────────────────────────────────────────────────
    // Storage  (namespaced to avoid upgrade slot collisions)
    // ─────────────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:zmail.storage.GaslessRelayer
    struct RelayerStorage {
        mapping(address => uint256) nonces;
        mapping(address => bool) trustedDomains; // only relay to registered domains
        bool paused;
    }

    // 
    bytes32 private constant RELAYER_STORAGE_SLOT =
        0x05069932bd6051a1aa7d860c00b996dbb069a775755c4feee7f3038de72663c2; // ^ keccak256("zmail.storage.GaslessRelayer") - 1  (computed off-chain, stored as constant)

    function _relayerStorage() private pure returns (RelayerStorage storage rs) {
        assembly { rs.slot := RELAYER_STORAGE_SLOT }
    }

    // ─────────────────────────────────────────────────────────────
    // EIP-712 type hash for the forward request
    // ─────────────────────────────────────────────────────────────

    bytes32 private constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 gas,"
        "uint256 nonce,uint256 deadline,bytes data)"
    );

    struct ForwardRequest {
        address from;
        address to; // must be a trustedDomain
        uint256 value; // always 0 for gasless
        uint256 gas;
        uint256 nonce;
        uint256 deadline;
        bytes data;
    }

        // ─────────────────────────────────────────────────────────────
    // Roles
    // ─────────────────────────────────────────────────────────────

    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ─────────────────────────────────────────────────────────────
    // Initializer
    // ─────────────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZMailTypes.ZMail__ZeroAddress();
        // __UUPSUpgradeable_init();
        __AccessControl_init();
        __EIP712_init("ZMailRelayer", "1");

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    // ─────────────────────────────────────────────────────────────
    // Public – relay
    // ─────────────────────────────────────────────────────────────

    /// @notice Execute a gasless meta-transaction.
    /// @param  req       The forward request signed by `req.from`.
    /// @param  signature EIP-712 signature over `req`.
    function execute(ForwardRequest calldata req, bytes calldata signature) external payable returns (bool success, bytes memory returndata) {
        RelayerStorage storage rs = _relayerStorage();
        if (rs.paused) revert ZMailTypes.ZMail__DomainPaused();
        if (!rs.trustedDomains[req.to]) revert ZMailTypes.ZMail__Unauthorized();
        if (block.timestamp > req.deadline) revert ZMailTypes.ZMail__SignatureExpired();
        if (req.nonce != rs.nonces[req.from]) revert ZMailTypes.ZMail__InvalidSignature();

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(abi.encode(
            FORWARD_REQUEST_TYPEHASH,
            req.from,
            req.to,
            req.value,
            req.gas,
            req.nonce,
            req.deadline,
            keccak256(req.data)
        ));
        address signer = _hashTypedDataV4(structHash).recover(signature);
        if (signer != req.from) revert ZMailTypes.ZMail__InvalidSignature();

        // Increment nonce before external call (CEI)
        unchecked { rs.nonces[req.from]++; }

        // Append original sender to calldata (EIP-2771)
        (success, returndata) = req.to.call{gas: req.gas, value: 0}(
            abi.encodePacked(req.data, req.from)
        );

        // Bubble revert
        if (!success) {
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Views
    // ─────────────────────────────────────────────────────────────

    function getNonce(address from) external view returns (uint256) {
        return _relayerStorage().nonces[from];
    }

    function isTrustedDomain(address domain) external view returns (bool) {
        return _relayerStorage().trustedDomains[domain];
    }

    // ─────────────────────────────────────────────────────────────
    // Admin
    // ─────────────────────────────────────────────────────────────
    
    function setTrustedDomain(address domain, bool trusted) external onlyRole(ADMIN_ROLE) {
        if (domain == address(0)) revert ZMailTypes.ZMail__ZeroAddress();
        _relayerStorage().trustedDomains[domain] = trusted;
        emit ZMailTypes.RelayerTrusted(domain, trusted);
    }

    function setPaused(bool paused) external onlyRole(ADMIN_ROLE) {
        _relayerStorage().paused = paused;
    }

    // ─────────────────────────────────────────────────────────────
    // UUPS upgrade guard
    // ─────────────────────────────────────────────────────────────
    function _authorizeUpgrade(address newImpl) internal view override onlyRole(ADMIN_ROLE) {
        if (newImpl == address(0)) revert ZMailTypes.ZMail__UpgradeNotAuthorized();
    }
}