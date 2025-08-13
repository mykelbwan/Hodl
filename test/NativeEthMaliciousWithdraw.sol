// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {HodlTestFile} from "../src/HodlTestFile.sol";

contract MaliciousWithdraw {
    HodlTestFile public hodl;
    address public targetToken;
    bool public attackInProgress;

    constructor(HodlTestFile _hodl, address _token) {
        hodl = _hodl;
        targetToken = _token;
    }

    // Receive ETH and try to reenter withdraw
    receive() external payable {
        if (!attackInProgress) {
            attackInProgress = true;
            hodl.withdraw(targetToken); // reenter attempt
        }
    }

    function startAttack() external {
        hodl.withdraw(address(0)); // address(0) = native ETH
    }
}
