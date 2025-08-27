// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {LeanIMT, LeanIMTData} from "../src/tree/LeanIMT.sol";
import {console} from "forge-std/console.sol";
import {TreeHelper} from "../src/TreeHelper.sol";

contract LeanIMTTest is Test {
    using LeanIMT for LeanIMTData;

    LeanIMTData public tree;
    LeanIMTData public tree10;

    function _fakeTree(LeanIMTData storage t, uint256 depth) internal {
        uint256[] memory sideNodes = new uint256[](depth);
        sideNodes[depth - 1] = TreeHelper.emptyNode(depth);
        t.initialize(depth, 1 << (depth - 1) + 1, sideNodes);
    }

    function setUp() public {
        _fakeTree(tree10, 30);
    }

    function test_InsertTree() public {
        uint256 leavesToInsert = 1000;
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < leavesToInsert; i++) {
            tree.insert(1337 + i);
        }
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertTree10() public {
        uint256 leavesToInsert = 1000;
        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < leavesToInsert; i++) {
            tree10.insert(1337 + i);
        }
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertManyTree() public {
        uint256 leavesToInsert = 1000;
        uint256[] memory leaves = new uint256[](leavesToInsert);
        for (uint256 i = 0; i < leavesToInsert; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 gasStart = gasleft();
        tree.insertMany(leaves);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_InsertManyTree10() public {
        uint256 leavesToInsert = 1000;
        uint256[] memory leaves = new uint256[](leavesToInsert);
        for (uint256 i = 0; i < leavesToInsert; i++) {
            leaves[i] = 1337 + i;
        }
        uint256 gasStart = gasleft();
        tree10.insertMany(leaves);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd) / leavesToInsert);
    }

    function test_UpdateTree() public {
        uint256 nLeaves = 1000;
        uint256[] memory leaves = new uint256[](nLeaves);
        for (uint256 i = 0; i < nLeaves; i++) {
            leaves[i] = i;
            tree.insert(leaves[i]);
        }
        uint256[] memory proof = TreeHelper.leanInclusionProof(leaves, 0);
        uint256 gasStart = gasleft();
        tree.update(0, 0, 1337, proof);
        uint256 gasEnd = gasleft();
        console.log("Gas used: %s", (gasStart - gasEnd));
    }
}
