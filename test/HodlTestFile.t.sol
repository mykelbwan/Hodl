// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {HodlTestFile} from "../src/HodlTestFile.sol";
import {DeployHodl} from "../script/DeployHodlTestFile.s.sol";
import {MockERC20} from "./MockERC20.sol";
import {MaliciousERC20} from "./MaliciousERC20.sol";
import {MaliciousWithdraw} from "./NativeEthMaliciousWithdraw.sol";

contract HodlTest is Test {
    HodlTestFile public hodl;
    MockERC20 internal mockToken;
    MaliciousWithdraw public attacker;
    address constant NATIVE_TOKEN = address(0);

    address user = makeAddr("user");
    address attackerAddress = makeAddr("attackerAddress");

    function setUp() public {
        DeployHodl deployHodl = new DeployHodl();
        hodl = deployHodl.run();
        vm.deal(user, 10 ether);
        vm.deal(attackerAddress, 10 ether);

        mockToken = new MockERC20("Mock Token", "MKT", 18);
        attacker = new MaliciousWithdraw(hodl, address(mockToken));
    }

    function testSecondsPerDayConstant() public view {
        /**
         * this is the var we are testing ->  uint256 constant SECONDS_PER_DAY = 24 * 60 * 60;
         */
        assertEq(hodl.SECONDS_PER_DAY(), 86400, "SECONDS_PER_DAY should equal 86400");
    }

    function testDepositNativeEth_Success() public {
        uint256 lockPeriod = 5; // days
        uint256 depositAmount = 0.5 ether;

        // Expect the Deposit event to be emitted
        vm.expectEmit(true, true, false, true);
        emit HodlTestFile.Deposit(user, NATIVE_TOKEN, depositAmount, lockPeriod);

        // Prank as the user and deposit ETH
        vm.prank(user);
        hodl.depositNativeEth{value: depositAmount}(lockPeriod);

        // Verify stored balance
        uint256 storedBalance = hodl.getBalance(user, NATIVE_TOKEN);
        console2.log(storedBalance);
        assertEq(storedBalance, depositAmount, "Balance not stored correctly");

        // Verify unlock time is correct
        uint256 storedUnlockTime = hodl.getLock(user, NATIVE_TOKEN);
        uint256 expectedUnlockTime = block.timestamp + hodl.daysToSeconds(lockPeriod);
        assertEq(storedUnlockTime, expectedUnlockTime, "Unlock time mismatch");
    }

    function testDepositNativeEth_FailWithDepositsPaused_ExpectRevert() public {
        uint256 lockPeriod = 5; // days
        uint256 depositAmount = 0.5 ether;

        /// @notice i sent the tx as msg.sender, cause only admin can change the state
        vm.prank(msg.sender);
        hodl.changeDepositState();
        vm.expectRevert();

        // Prank as the user and deposit ETH
        vm.prank(user);
        ///@notice this tx should revert because deposits are currently not being accepted
        hodl.depositNativeEth{value: depositAmount}(lockPeriod);
    }

    function testDepositNativeEth_RevertWhenAmountZero() public {
        uint256 lockPeriod = 3;

        // Expect revert if no ETH is sent
        vm.expectRevert(HodlTestFile.Hodl__AmountExpected.selector);
        vm.prank(user);
        hodl.depositNativeEth{value: 0}(lockPeriod);
    }

    function testDepositErc20_Success() public {
        uint256 lockPeriod = 7; // days
        uint256 depositAmount = 100 ether;

        mockToken.mint(user, depositAmount);

        // User approves HodlTestFile to spend ERC20
        vm.startPrank(user);
        mockToken.approve(address(hodl), depositAmount);

        // Expect the Deposit event
        vm.expectEmit(true, true, false, true);
        emit HodlTestFile.Deposit(user, address(mockToken), depositAmount, lockPeriod);

        // Call depositErc20
        hodl.depositErc20(address(mockToken), depositAmount, lockPeriod);
        vm.stopPrank();

        // --- Assertions ---
        assertEq(hodl.getBalance(user, address(mockToken)), depositAmount, "ERC20 balance mismatch");

        uint256 expectedUnlock = block.timestamp + hodl.daysToSeconds(lockPeriod);
        assertEq(hodl.getLock(user, address(mockToken)), expectedUnlock, "Unlock time mismatch");

        assertEq(mockToken.balanceOf(address(hodl)), depositAmount, "HodlTestFile contract did not receive tokens");
    }

    function testDepositErc20_RevertWhenAmountZero() public {
        uint256 lockPeriod = 5;

        mockToken.mint(user, 1 ether);

        vm.startPrank(user);
        mockToken.approve(address(hodl), 1 ether);

        vm.expectRevert(HodlTestFile.Hodl__AmountExpected.selector);
        hodl.depositErc20(address(mockToken), 0, lockPeriod);
        vm.stopPrank();
    }

    function testNonReentrantBlocksAttack() public {
        // Deposit native ETH as attacker
        vm.deal(address(attackerAddress), 1 ether);
        vm.prank(address(attackerAddress));
        hodl.depositNativeEth{value: 1 ether}(0);

        // Expect revert due to nonReentrant on reentrant withdraw()
        vm.expectRevert();
        attacker.startAttack();
    }

    function testWithdrawWithNonReentrant() public {
        uint256 amount = 100 ether;
        uint256 lockPeriod = 0;

        // Mint + approve
        mockToken.mint(address(this), amount);
        mockToken.approve(address(hodl), amount);

        // Deposit ERC20
        hodl.depositErc20(address(mockToken), amount, lockPeriod);

        // Withdraw (happy path)
        uint256 preBalance = mockToken.balanceOf(address(this));
        hodl.withdraw(address(mockToken));
        uint256 postBalance = mockToken.balanceOf(address(this));

        assertEq(postBalance, preBalance + amount, "Tokens not returned");
        assertEq(hodl.getBalance(address(this), address(mockToken)), 0, "Balance not reset");

        // Token address list should be cleared
        address[] memory tokens = hodl.getUserTokens(address(this));
        assertEq(tokens.length, 0, "Token list not cleared");
    }

    function testWithdrawRevertsWhenNoBalance() public {
        vm.expectRevert(HodlTestFile.Hodl__NoBalance.selector);
        hodl.withdraw(address(mockToken));
    }

    function testWithdrawRevertsWhenLockNotMature() public {
        uint256 amount = 100 ether;
        uint256 lockPeriod = 1 days;

        mockToken.mint(address(this), amount);
        mockToken.approve(address(hodl), amount);
        hodl.depositErc20(address(mockToken), amount, lockPeriod);

        vm.expectRevert(HodlTestFile.Hodl__LockNotMature.selector);
        hodl.withdraw(address(mockToken));
    }

    function testNonReentrantBlocksERC20Attack() public {
        // Deploy malicious ERC20
        MaliciousERC20 malToken = new MaliciousERC20("Evil Token", "EVIL");

        // Set target HodlTestFile + token
        malToken.setTarget(hodl, address(malToken));

        // Mint to this test contract
        malToken.mint(address(this), 50 ether);

        // Approve + deposit into HodlTestFile
        malToken.approve(address(hodl), 50 ether);
        hodl.depositErc20(address(malToken), 50 ether, 0);

        // Expect revert when trying to withdraw — due to nonReentrant blocking the reentry
        vm.expectRevert();
        hodl.withdraw(address(malToken));
    }

    function testReceiveFunction() public {
        // Send ETH directly with no calldata to trigger receive()
        vm.prank(user);
        (bool success,) = address(hodl).call{value: 1 ether}("");
        assertTrue(success, "Receive function failed");

        // Verify deposit was recorded
        uint256 balance = hodl.getBalance(user, NATIVE_TOKEN);
        assertEq(balance, 1 ether, "Native ETH deposit via receive() mismatch");
    }

    function testLockMaturity() public {
        // Set a high enough starting timestamp to avoid underflow
        uint256 nowTs = 1000000; // > 86400
        vm.warp(nowTs);

        uint256 futureTimestamp = nowTs + 1 days;
        uint256 pastTimestamp = nowTs - 1 days;

        // Not mature yet
        bool notMature = hodl.lockMaturity(futureTimestamp);
        assertFalse(notMature, "Expected lock not to be mature yet");

        // Already mature
        bool mature = hodl.lockMaturity(pastTimestamp);
        assertTrue(mature, "Expected lock to be mature");
    }

    function testLockMaturity_Fuzz(uint256 unlockTimestamp) public view {
        uint256 nowTs = block.timestamp;

        bool result = hodl.lockMaturity(unlockTimestamp);

        if (unlockTimestamp <= nowTs) {
            // If unlock time is now or in the past → should be mature
            assertTrue(result, "Expected maturity when unlock <= now");
        } else {
            // If unlock time is in the future → should not be mature
            assertFalse(result, "Expected not mature when unlock > now");
        }
    }

    function testCanWithdraw_FalseBeforeUnlock() public {
        // Simulate msg.sender as `user`
        vm.startPrank(user);

        // Pretend unlockTime[user][token] is in the future
        hodl.setUnlockTime(user, address(mockToken), block.timestamp + 10 days);

        bool result = hodl.canWithdraw(user, address(mockToken));
        assertFalse(result, "Should not be able to withdraw before unlock");

        vm.stopPrank();
    }

    function testCanWithdraw_TrueAfterUnlock() public {
        vm.startPrank(user);

        // Pretend unlock time is in the past
        hodl.setUnlockTime(user, address(mockToken), 0 days);

        bool result = hodl.canWithdraw(user, address(mockToken));
        assertTrue(result, "Should be able to withdraw after unlock");

        vm.stopPrank();
    }

    function testDaysToSeconds() public view {
        // 1 day = 86400 seconds
        assertEq(hodl.daysToSeconds(1), 86400, "1 day mismatch");

        // 0 days = 0 seconds
        assertEq(hodl.daysToSeconds(0), 0, "0 days mismatch");

        // 7 days = 604800 seconds
        assertEq(hodl.daysToSeconds(7), 604800, "7 days mismatch");

        // Large number test (1000 days)
        assertEq(hodl.daysToSeconds(1000), 86_400_000, "1000 days mismatch");
    }

    function testGetBalance_NoDeposit() public view {
        uint256 balance = hodl.getBalance(user, NATIVE_TOKEN);
        assertEq(balance, 0, "Expected 0 balance when no deposit made");
    }

    function testGetBalance_AfterDeposit() public {
        uint256 depositAmount = 0.5 ether;

        // Deposit ETH (no lock for simplicity)
        vm.prank(user);
        hodl.depositNativeEth{value: depositAmount}(0);

        uint256 balance = hodl.getBalance(user, NATIVE_TOKEN);
        assertEq(balance, depositAmount, "Balance mismatch after deposit");
    }

    function testGetUserBalances() public {
        uint256 ethDepositAmount = 0.5 ether;
        uint256 ethLockPeriod = 5; // days

        mockToken.mint(user, 1000 ether);

        uint256 erc20DepositAmount = 200 ether;
        uint256 erc20LockPeriod = 10; // days

        // ----- Deposit Native ETH -----
        vm.prank(user);
        hodl.depositNativeEth{value: ethDepositAmount}(ethLockPeriod);

        // ----- Deposit ERC20 -----
        vm.startPrank(user);
        mockToken.approve(address(hodl), erc20DepositAmount);
        hodl.depositErc20(address(mockToken), erc20DepositAmount, erc20LockPeriod);
        vm.stopPrank();

        // ----- Call getUserBalances -----
        (address[] memory tokens, uint256[] memory amounts, uint256[] memory locks) = hodl.getUserBalances(user);

        // ----- Assertions -----
        assertEq(tokens.length, 2, "Token array length mismatch");
        assertEq(amounts.length, 2, "Amounts array length mismatch");
        assertEq(locks.length, 2, "Locks array length mismatch");

        // Check ETH deposit entry
        assertEq(tokens[0], NATIVE_TOKEN, "ETH token address mismatch");
        assertEq(amounts[0], ethDepositAmount, "ETH amount mismatch");
        assertEq(locks[0], block.timestamp + hodl.daysToSeconds(ethLockPeriod), "ETH lock time mismatch");

        // Check ERC20 deposit entry
        assertEq(tokens[1], address(mockToken), "ERC20 token address mismatch");
        assertEq(amounts[1], erc20DepositAmount, "ERC20 amount mismatch");
        assertEq(locks[1], block.timestamp + hodl.daysToSeconds(erc20LockPeriod), "ERC20 lock time mismatch");
    }

    function testGetLock_NoDeposit() public view {
        uint256 lock = hodl.getLock(user, NATIVE_TOKEN);
        assertEq(lock, 0, "Expected 0 lock time when no deposit made");
    }

    function testGetLock_AfterDeposit() public {
        uint256 lockPeriod = 5; // days
        uint256 depositAmount = 0.5 ether;

        // Deposit ETH with lock period
        vm.prank(user);
        hodl.depositNativeEth{value: depositAmount}(lockPeriod);

        uint256 expectedUnlock = block.timestamp + hodl.daysToSeconds(lockPeriod);
        uint256 lock = hodl.getLock(user, NATIVE_TOKEN);

        assertEq(lock, expectedUnlock, "Unlock time mismatch after deposit");
    }

    function testFirstDeposit() public {
        uint256 amount = 100 ether;
        uint256 lockPeriod = 10; // days

        vm.warp(1_000_000); // Set starting timestamp

        hodl.setDeposit(user, address(mockToken), amount, lockPeriod);

        // Check deposit balance
        assertEq(hodl.getBalance(user, address(mockToken)), amount);

        // Expected unlock time = start + lockPeriodDays in seconds
        uint256 expectedUnlock = 1_000_000 + (lockPeriod * 1 days);
        assertEq(hodl.getLock(user, address(mockToken)), expectedUnlock);

        // Token should be in token list
        address[] memory tokens = hodl.getUserTokens(user);
        assertEq(tokens.length, 1);
        assertEq(tokens[0], address(mockToken));
    }

    function testChangeAdmin_ExpectRevert() public {
        vm.expectRevert();
        hodl.changeAdmin(user);
    }

    function testChangeAdminSuccess() public {
        vm.prank(msg.sender);
        hodl.changeAdmin(user);

        assertEq(hodl.getAdmin(), user);
    }

    function testChangeDepositState_ExpectRevert() public {
        vm.expectRevert();
        hodl.changeDepositState();
    }

    function testChangeWithdrawalState_ExpectRevert() public {
        vm.expectRevert();
        hodl.changeWithdrawalState();
    }
}
