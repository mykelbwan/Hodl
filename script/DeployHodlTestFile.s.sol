// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {HodlTestFile} from "../src/HodlTestFile.sol";

contract DeployHodl is Script {
    HodlTestFile public hodl;

    function setUp() public {}

    function run() public returns (HodlTestFile) {
        vm.startBroadcast();

        hodl = new HodlTestFile();

        vm.stopBroadcast();

        return hodl;
    }
}
