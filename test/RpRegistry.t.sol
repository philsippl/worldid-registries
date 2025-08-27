// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {RpRegistry} from "../src/RpRegistry.sol";

contract RpRegistryTest is Test {
    RpRegistry private registry;

    // EIP712 Domain typehash
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() public {
        registry = new RpRegistry();
    }

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 nameHash = keccak256(bytes(registry.EIP712_NAME()));
        bytes32 versionHash = keccak256(bytes(registry.EIP712_VERSION()));
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(registry)));
    }

    function _signRemove(uint256 pk, uint256 rpId) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(registry.REMOVE_RP_TYPEHASH(), rpId));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdatePubkey(uint256 pk, uint256 rpId, bytes32 newPubkey, bytes32 oldPubkey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(registry.UPDATE_PUBKEY_TYPEHASH(), rpId, newPubkey, oldPubkey));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdateSigner(uint256 pk, uint256 rpId, address newSigner) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(registry.UPDATE_SIGNER_TYPEHASH(), rpId, newSigner));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testRegisterAndGetters() public {
        uint256 signerPk = 0xA11CE;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("pubkey-1");

        vm.expectEmit();
        emit RpRegistry.RpRegistered(1, pubkey, signer);
        registry.register(pubkey, signer);

        assertEq(registry.nextRpId(), 2);
        assertEq(registry.rpIdToPubkey(1), pubkey);
        assertEq(registry.addressToRpId(signer), 1);
    }

    function testRegisterRevertsOnZeroOrDuplicate() public {
        uint256 signerPk = 0xB0B;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("pubkey-2");

        vm.expectRevert(bytes("Registry: pubkey cannot be zero"));
        registry.register(bytes32(0), signer);

        registry.register(pubkey, signer);

        vm.expectRevert(bytes("Registry: signer already registered"));
        registry.register(keccak256("another"), signer);
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xC0FFEE;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("old");
        registry.register(pubkey, signer);

        bytes32 newPubkey = keccak256("new");
        bytes memory sig = _signUpdatePubkey(signerPk, 1, newPubkey, pubkey);

        vm.expectEmit();
        emit RpRegistry.PubkeyUpdated(1, pubkey, newPubkey, signer);
        registry.updatePubkey(1, newPubkey, sig);

        assertEq(registry.rpIdToPubkey(1), newPubkey);
    }

    function testUpdatePubkeyRevertsOnBadSig() public {
        uint256 goodPk = 0xD00D;
        uint256 badPk = 0xBAD;
        address signer = vm.addr(goodPk);
        registry.register(keccak256("k"), signer);

        bytes32 newPubkey = keccak256("new");
        bytes memory sig = _signUpdatePubkey(badPk, 1, newPubkey, keccak256("k"));

        vm.expectRevert(bytes("Registry: invalid signature"));
        registry.updatePubkey(1, newPubkey, sig);
    }

    function testUpdateSignerFlow() public {
        uint256 oldPk = 0x1111;
        address oldSigner = vm.addr(oldPk);
        registry.register(keccak256("k"), oldSigner);

        address newSigner = vm.addr(0x2222);
        bytes memory sig = _signUpdateSigner(oldPk, 1, newSigner);

        vm.expectEmit();
        emit RpRegistry.SignerUpdated(1, oldSigner, newSigner);
        registry.updateSigner(1, newSigner, sig);

        assertEq(registry.addressToRpId(oldSigner), 0);
        assertEq(registry.addressToRpId(newSigner), 1);
    }

    function testRemoveFlow() public {
        uint256 signerPk = 0x3333;
        address signer = vm.addr(signerPk);
        bytes32 pubkey = keccak256("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRemove(signerPk, 1);

        vm.expectEmit();
        emit RpRegistry.RpRemoved(1, pubkey, signer);
        registry.remove(1, sig);

        assertEq(registry.rpIdToPubkey(1), bytes32(0));
        assertEq(registry.addressToRpId(signer), 0);
    }
}
