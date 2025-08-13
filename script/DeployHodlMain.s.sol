// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {Hodl} from "../src/Hodl.sol";

contract DeployHodl is Script {
    Hodl public hodl;

    function setUp() public {}

    function run() public returns (Hodl) {
        vm.startBroadcast();
        hodl = new Hodl();
        vm.stopBroadcast();
        return hodl;
    }
}
