// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";
import {Poseidon2T2} from "../src/hash/Poseidon2.sol";
import {Poseidon2T2Reference} from "../src/hash/Poseidon2Reference.sol";
import {Skyscraper} from "../src/hash/Skyscraper.sol";

contract LeanIMTTest is Test {
    uint256 constant HASH_COUNT = 1000;

    function setUp() public {}

    function test_Skyscraper() public {
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            Skyscraper.compress(uint256(0), uint256(0));
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

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

    function test_Poseidon2T2() public {
        uint256[2] memory inputs = [uint256(0), uint256(0)];
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            Poseidon2T2.compress(inputs);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_Poseidon2T2Reference() public {
        uint256[2] memory inputs = [uint256(0), uint256(0)];
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            Poseidon2T2Reference.compress(inputs);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_Poseidon2T2EqualsReference() public {
        uint256[2] memory inputs = [uint256(0xDEADBEEF), uint256(0x12345678)];
        uint256 result = Poseidon2T2.compress(inputs);
        uint256 resultReference = Poseidon2T2Reference.compress(inputs);
        assertEq(result, resultReference);
    }
}
