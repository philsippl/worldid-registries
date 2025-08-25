// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AuthenticatorRegistry} from "../src/AuthenticatorRegistry.sol";

contract AuthenticatorRegistryTest is Test {
    AuthenticatorRegistry public authenticatorRegistry;

    function setUp() public {
        authenticatorRegistry = new AuthenticatorRegistry();
    }

    function test_CreateAccount() public {
        authenticatorRegistry.createAccount(address(1), new address[](1), 1);
    }

    function test_CreateManyAccounts() public {
        authenticatorRegistry.createManyAccounts(new address[](1), new address[][](1), new uint256[](1));
    }
}
