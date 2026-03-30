// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title  ZMailTypes
/// @notice Shared structs, events, custom errors, and constants for the ZMail protocol.
///         Centralising here avoids import cycles and keeps individual contracts lean.
library ZMailTypes {
    // ─────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────

    /// @dev Core envelope stored on-chain. Message body is FHE-encrypted and stored
    ///      as raw ciphertext bytes so only the recipient's FHE key can decrypt it.
    struct MailEnvelope {
        uint256 id; // monotonically increasing per-domain ID
        address sender; // msg.sender or recovered meta-tx signer
        address recipient; // resolved address of the recipient alias
        bytes32 subjectHash; // keccak256 of encrypted subject (enables on-chain search)
        bytes ciphertext;    // coFHE-encrypted body (euint8[] packed)
        bytes32 attachmentRoot; // merkle root of attachment CIDs (0x0 if none)
        uint48 sentAt; // block.timestamp, capped at uint48
        bool isRead;
        bool isDeleted;
        uint8 flags; // bitmask: 0x01=starred, 0x02=spam, 0x04=archived
    }

    /// @dev Represents a user identity inside a domain
    struct Identity {
        address owner; // wallet address
        bytes fhePublicKey; // coFHE public key submitted by client
        uint48 registeredAt;
        bool active;
        uint32 inboxCount;
        uint32 sentCount;
    }

    /// @dev Per-domain configuration; stored in EmailDomain
    struct DomainConfig {
        string name; // e.g. "zmail.eth"
        address admin;
        uint32 maxAliasLength;
        uint32 maxMailboxSize; // max envelopes stored per user before auto-archive
        bool openRegistration; // anyone can register, vs whitelist
        bool paused;
    }

    /// @dev Attachment descriptor stored in AttachmentRegistry.
    struct Attachment {
        bytes32 cid; // IPFS / Arweave CID (keccak256 of raw CID string)
        bytes encryptedKey; // FHE-encrypted symmetric decryption key
        uint64 sizeBytes;
        string mimeType;
    }

    // ─────────────────────────────────────────────────────────────
    // Events  (emitted from children but declared here for consistency)
    // ─────────────────────────────────────────────────────────────

    event MailSent (
        address indexed domainContract,
        uint256 indexed mailId,
        address indexed sender,
        address recipient,
        bytes32 subjectHash,
        uint48 sentAt
    );
    event MailDeleted(address indexed domainContract, uint256 indexed mailId, address indexed owner);
    event MailRead(address indexed domainContract, uint256 indexed mailId, address indexed reader);
    event MailFlagged(address indexed domainContract, uint256 indexed mailId, uint8 flags);

    event IdentityRegistered(address indexed domainContract, address indexed owner, string alias_);
    event IdentityRevoked(address indexed domainContract, address indexed owner);
    event FHEKeyUpdated(address indexed domainContract, address indexed owner);

    event DomainDeployed(address indexed factory, address indexed domain, string name);
    event DomainUpgraded(address indexed domain, address indexed newImpl);
    event DomainPaused(address indexed domain);
    event DomainUnpaused(address indexed domain);

    event AttachmentRegistered(bytes32 indexed cid, address indexed uploader, uint256 indexed mailId);
    event RelayerTrusted(address indexed relayer, bool trusted);

    // ─────────────────────────────────────────────────────────────
    // Custom errors  (saves ~20-40 gas vs string revert)
    // ─────────────────────────────────────────────────────────────

    error ZMail__Unauthorized();
    error ZMail__AlreadyRegistered();
    error ZMail__NotRegistered();
    error ZMail__DomainPaused();
    error ZMail__InvalidAlias();
    error ZMail__AliasTooLong();
    error ZMail__RecipientNotFound();
    error ZMail__MailNotFound();
    error ZMail__NotOwner();
    error ZMail__AlreadyDeleted();
    error ZMail__EmptyCiphertext();
    error ZMail__AttachmentLimitExceeded();
    error ZMail__RateLimitExceeded();
    error ZMail__InvalidSignature();
    error ZMail__SignatureExpired();
    error ZMail__DomainAlreadyExists();
    error ZMail__InvalidDomainName();
    error ZMail__ZeroAddress();
    error ZMail__InvalidFHEKey();
    error ZMail__MailboxFull();
    error ZMail__SelfSend();
    error ZMail__NotFactory();
    error ZMail__UpgradeNotAuthorized();

    // ─────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────

    uint8  internal constant MAX_ATTACHMENTS_PER_MAIL = 10;
    uint32 internal constant DEFAULT_MAX_MAILBOX_SIZE  = 10_000;
    uint32 internal constant DEFAULT_MAX_ALIAS_LENGTH  = 32;
    uint256 internal constant RATE_LIMIT_WINDOW        = 1 hours;
    uint256 internal constant RATE_LIMIT_MAX_SENDS     = 100;

    // EIP-712 type hashes
    bytes32 internal constant MAIL_TYPEHASH = keccak256(
        "Mail(address from,address to,bytes32 subjectHash,bytes32 ciphertextHash,"
        "bytes32 attachmentRoot,uint256 nonce,uint256 deadline)"
    );

    bytes32 internal constant REGISTER_TYPEHASH = keccak256(
        "Register(address owner,string alias,bytes fhePublicKey,uint256 nonce,uint256 deadline)"
    );
}