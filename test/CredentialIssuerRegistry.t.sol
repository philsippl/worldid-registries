// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CredentialIssuerRegistry} from "../src/CredentialIssuerRegistry.sol";

contract CredentialIssuerRegistryTest is Test {
    CredentialIssuerRegistry private registry;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() public {
        registry = new CredentialIssuerRegistry();
    }

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 nameHash = keccak256(bytes(registry.EIP712_NAME()));
        bytes32 versionHash = keccak256(bytes(registry.EIP712_VERSION()));
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(registry)));
    }

    function _signRemove(uint256 pk, uint256 issuerId) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(registry.REMOVE_ISSUER_TYPEHASH(), issuerId, registry.nonceOf(issuerId)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdatePubkey(uint256 pk, uint256 issuerId, bytes32 newPubkey, bytes32 oldPubkey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(registry.UPDATE_PUBKEY_TYPEHASH(), issuerId, newPubkey, oldPubkey, registry.nonceOf(issuerId))
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdateSigner(uint256 pk, uint256 issuerId, address newSigner) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_SIGNER_TYPEHASH(), issuerId, newSigner, registry.nonceOf(issuerId)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testRegisterAndGetters() public {
        uint256 signerPk = 0xAAA1;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("pubkey-issuer-1");

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerRegistered(1, pubkey, signer);
        registry.register(pubkey, signer);

        assertEq(registry.nextIssuerId(), 2);
        assertEq(registry.issuerIdToPubkey(1), pubkey);
        assertEq(registry.addressToIssuerId(signer), 1);
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xAAA2;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("old");
        registry.register(pubkey, signer);

        bytes32 newPubkey = keccak256("new");
        bytes memory sig = _signUpdatePubkey(signerPk, 1, newPubkey, pubkey);

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerPubkeyUpdated(1, pubkey, newPubkey, signer);
        registry.updatePubkey(1, newPubkey, sig);

        assertEq(registry.issuerIdToPubkey(1), newPubkey);
    }

    function testUpdateSignerFlow() public {
        uint256 oldPk = 0xAAA3;
        address oldSigner = vm.addr(oldPk);
        registry.register(keccak256("k"), oldSigner);

        address newSigner = vm.addr(0xAAA4);
        bytes memory sig = _signUpdateSigner(oldPk, 1, newSigner);

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerSignerUpdated(1, oldSigner, newSigner);
        registry.updateSigner(1, newSigner, sig);

        assertEq(registry.addressToIssuerId(oldSigner), 0);
        assertEq(registry.addressToIssuerId(newSigner), 1);
    }

    function testRemoveFlow() public {
        uint256 signerPk = 0xAAA5;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRemove(signerPk, 1);

        vm.expectEmit();
        emit CredentialIssuerRegistry.IssuerRemoved(1, pubkey, signer);
        registry.remove(1, sig);

        assertEq(registry.issuerIdToPubkey(1), bytes32(0));
        assertEq(registry.addressToIssuerId(signer), 0);
    }
}
