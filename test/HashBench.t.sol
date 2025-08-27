// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";

contract LeanIMTTest is Test {
    uint256 constant HASH_COUNT = 1000;

    function setUp() public {}

    function test_PoseidonT3() public {
        uint256[2] memory inputs = [uint256(0), uint256(0)];
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            PoseidonT3.hash(inputs);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_PoseidonT4() public {
        uint256[3] memory inputs = [uint256(0), uint256(0), uint256(0)];
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            PoseidonT4.hash(inputs);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }
}
