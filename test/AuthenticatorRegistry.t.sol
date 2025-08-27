// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AuthenticatorRegistry} from "../src/AuthenticatorRegistry.sol";
import {TreeHelper} from "../src/TreeHelper.sol";

contract AuthenticatorRegistryTest is Test {
    AuthenticatorRegistry public authenticatorRegistry;

    address public constant DEFAULT_RECOVERY_ADDRESS = address(0xDEADBEEF);
    address public constant RECOVERY_ADDRESS = address(0xDEADBEEF);
    address public AUTHENTICATOR_ADDRESS1;
    address public AUTHENTICATOR_ADDRESS2;
    uint256 public constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;
    uint256 public constant AUTH1_PRIVATE_KEY = 0x01;
    uint256 public constant AUTH2_PRIVATE_KEY = 0x02;

    function setUp() public {
        authenticatorRegistry = new AuthenticatorRegistry();
        AUTHENTICATOR_ADDRESS1 = vm.addr(AUTH1_PRIVATE_KEY);
        AUTHENTICATOR_ADDRESS2 = vm.addr(AUTH2_PRIVATE_KEY);
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

    function eip712Sign(bytes32 typeHash, bytes memory data, uint256 privateKey) private returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", authenticatorRegistry.domainSeparatorV4(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function updateAuthenticatorProofAndSignature(uint256 accountIndex, uint256 nonce)
        private
        returns (bytes memory, uint256[] memory)
    {
        bytes memory signature = eip712Sign(
            authenticatorRegistry.UPDATE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS1, AUTHENTICATOR_ADDRESS2, OFFCHAIN_SIGNER_COMMITMENT, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256[] memory leaves = new uint256[](1);
        leaves[0] = OFFCHAIN_SIGNER_COMMITMENT;
        uint256[] memory proof = TreeHelper.leanInclusionProof(leaves, 0);

        return (signature, proof);
    }

    ////////////////////////////////////////////////////////////
    //                        Tests                           //
    ////////////////////////////////////////////////////////////

    function test_CreateAccount() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(address(0), authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);
    }

    function test_CreateManyAccounts() public {
        address[] memory recoveryAddresses = new address[](2);
        address[][] memory authenticatorAddresses = new address[][](2);
        authenticatorAddresses[0] = new address[](1);
        authenticatorAddresses[0][0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = new address[](1);
        authenticatorAddresses[1][0] = AUTHENTICATOR_ADDRESS2;
        uint256[] memory offchainSignerCommitments = new uint256[](2);
        offchainSignerCommitments[0] = OFFCHAIN_SIGNER_COMMITMENT;
        offchainSignerCommitments[1] = OFFCHAIN_SIGNER_COMMITMENT;
        authenticatorRegistry.createManyAccounts(recoveryAddresses, authenticatorAddresses, offchainSignerCommitments);
    }

    function test_UpdateAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 0;
        uint256 accountIndex = 1;

        // AUTHENTICATOR_ADDRESS1 is assigned to account 1
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);

        (bytes memory signature, uint256[] memory proof) = updateAuthenticatorProofAndSignature(accountIndex, nonce);

        authenticatorRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            signature,
            proof,
            nonce
        );

        // AUTHENTICATOR_ADDRESS1 has been removed
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS1), 0);
        // AUTHENTICATOR_ADDRESS2 has been added
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS2), 1);
    }

    function test_UpdateAuthenticatorInvalidAccountIndex() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 0;
        uint256 accountIndex = 2;

        (bytes memory signature, uint256[] memory proof) = updateAuthenticatorProofAndSignature(accountIndex, nonce);

        vm.expectRevert("Invalid account index");

        authenticatorRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            signature,
            proof,
            nonce
        );
    }

    function test_UpdateAuthenticatorInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 1;
        uint256 accountIndex = 1;

        // AUTHENTICATOR_ADDRESS1 is assigned to account 1
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);

        (bytes memory signature, uint256[] memory proof) = updateAuthenticatorProofAndSignature(accountIndex, nonce);

        vm.expectRevert("Invalid nonce");

        authenticatorRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            signature,
            proof,
            nonce
        );
    }

    function test_InsertAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;

        bytes memory signature = eip712Sign(
            authenticatorRegistry.INSERT_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS2, OFFCHAIN_SIGNER_COMMITMENT, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256[] memory leaves = new uint256[](1);
        leaves[0] = OFFCHAIN_SIGNER_COMMITMENT;
        uint256[] memory proof = TreeHelper.leanInclusionProof(leaves, 0);

        authenticatorRegistry.insertAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            signature,
            proof,
            nonce
        );

        // Both authenticators should now belong to the same account
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS2), accountIndex);
    }

    function test_RemoveAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = AUTHENTICATOR_ADDRESS2;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;

        bytes memory signature = eip712Sign(
            authenticatorRegistry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS2, OFFCHAIN_SIGNER_COMMITMENT, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256[] memory leaves = new uint256[](1);
        leaves[0] = OFFCHAIN_SIGNER_COMMITMENT;
        uint256[] memory proof = TreeHelper.leanInclusionProof(leaves, 0);

        authenticatorRegistry.removeAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            signature,
            proof,
            nonce
        );

        // AUTHENTICATOR_ADDRESS2 should be removed; AUTHENTICATOR_ADDRESS1 remains
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS2), 0);
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);
    }

    function test_RecoverAccountSuccess() public {
        // Use a recovery address we control via a known private key
        uint256 RECOVERY_PRIVATE_KEY = 0xA11CE;
        address recoverySigner = vm.addr(RECOVERY_PRIVATE_KEY);

        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = AUTHENTICATOR_ADDRESS2;
        authenticatorRegistry.createAccount(recoverySigner, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        address NEW_AUTHENTICATOR = address(0xBEEF);

        bytes memory signature = eip712Sign(
            authenticatorRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(accountIndex, NEW_AUTHENTICATOR, OFFCHAIN_SIGNER_COMMITMENT, nonce),
            RECOVERY_PRIVATE_KEY
        );

        uint256[] memory leaves = new uint256[](1);
        leaves[0] = OFFCHAIN_SIGNER_COMMITMENT;
        uint256[] memory proof = TreeHelper.leanInclusionProof(leaves, 0);

        authenticatorRegistry.recoverAccount(
            accountIndex,
            NEW_AUTHENTICATOR,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            signature,
            proof,
            nonce
        );

        // Old authenticators removed
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS1), 0);
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(AUTHENTICATOR_ADDRESS2), 0);
        // New authenticator added
        assertEq(authenticatorRegistry.authenticatorAddressToAccountIndex(NEW_AUTHENTICATOR), accountIndex);
    }
}
