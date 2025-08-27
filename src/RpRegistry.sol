// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {AbstractSignerPubkeyRegistry} from "./AbstractSignerPubkeyRegistry.sol";

contract RpRegistry is AbstractSignerPubkeyRegistry {
    // Keep constants and events for ABI stability and off-chain use
    string public constant EIP712_NAME = "RpRegistry";
    string public constant EIP712_VERSION = "1.0";

    string public constant REMOVE_RP_TYPEDEF = "RemoveRp(uint256 rpId)";
    string public constant UPDATE_PUBKEY_TYPEDEF = "UpdatePubkey(uint256 rpId, bytes32 newPubkey, bytes32 oldPubkey)";
    string public constant UPDATE_SIGNER_TYPEDEF = "UpdateSigner(uint256 rpId, address newSigner)";

    bytes32 public constant REMOVE_RP_TYPEHASH = keccak256(abi.encodePacked(REMOVE_RP_TYPEDEF));
    bytes32 public constant UPDATE_PUBKEY_TYPEHASH = keccak256(abi.encodePacked(UPDATE_PUBKEY_TYPEDEF));
    bytes32 public constant UPDATE_SIGNER_TYPEHASH = keccak256(abi.encodePacked(UPDATE_SIGNER_TYPEDEF));

    event RpRegistered(uint256 indexed rpId, bytes32 pubkey, address signer);
    event RpRemoved(uint256 indexed rpId, bytes32 pubkey, address signer);
    event PubkeyUpdated(uint256 indexed rpId, bytes32 oldPubkey, bytes32 newPubkey, address signer);
    event SignerUpdated(uint256 indexed rpId, address oldSigner, address newSigner);

    constructor() AbstractSignerPubkeyRegistry(EIP712_NAME, EIP712_VERSION) {}

    function rpIdToPubkey(uint256 rpId) public view returns (bytes32) {
        return _idToPubkey[rpId];
    }

    function addressToRpId(address signer) public view returns (uint256) {
        return _addressToId[signer];
    }

    function nextRpId() public view returns (uint256) {
        return _nextId;
    }

    function _typehashRemove() internal pure override returns (bytes32) {
        return REMOVE_RP_TYPEHASH;
    }

    function _typehashUpdatePubkey() internal pure override returns (bytes32) {
        return UPDATE_PUBKEY_TYPEHASH;
    }

    function _typehashUpdateSigner() internal pure override returns (bytes32) {
        return UPDATE_SIGNER_TYPEHASH;
    }

    function _emitRegistered(uint256 id, bytes32 pubkey, address signer) internal override {
        emit RpRegistered(id, pubkey, signer);
    }

    function _emitRemoved(uint256 id, bytes32 pubkey, address signer) internal override {
        emit RpRemoved(id, pubkey, signer);
    }

    function _emitPubkeyUpdated(uint256 id, bytes32 oldPubkey, bytes32 newPubkey, address signer) internal override {
        emit PubkeyUpdated(id, oldPubkey, newPubkey, signer);
    }

    function _emitSignerUpdated(uint256 id, address oldSigner, address newSigner) internal override {
        emit SignerUpdated(id, oldSigner, newSigner);
    }
}
