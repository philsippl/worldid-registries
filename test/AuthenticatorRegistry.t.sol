// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AuthenticatorRegistry} from "../src/AuthenticatorRegistry.sol";

contract AuthenticatorRegistryTest is Test {
    AuthenticatorRegistry public authenticatorRegistry;

    address public constant DEFAULT_RECOVERY_ADDRESS = address(0xDEADBEEF);
    address public constant RECOVERY_ADDRESS = address(0xDEADBEEF);
    address public constant AUTHENTICATOR_ADDRESS1 = address(0xBEEFDEAD1);
    address public constant AUTHENTICATOR_ADDRESS2 = address(0xBEEFDEAD2);
    uint256 public constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;

    function setUp() public {
        authenticatorRegistry = new AuthenticatorRegistry(DEFAULT_RECOVERY_ADDRESS);
    }

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
}
