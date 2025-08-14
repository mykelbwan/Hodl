# **Hodl** smart contract (wack name ikr) is a experimental project i worked on in my second week of learning solidity from **patrick colins** on yt, ty to you Sir..

# I had an idea when i see some of my friends buy and sell their wife making tokens for gas fees, so i made Hodl. Hodl essentially locks your **moonbag** for your specified lock duration or leave the lock period at 0.

# This contract was thought and implemented with best security practices as i had learned from mr **patrick** and i also i'm reading the solidity docs, which is amazing and easy to understand.. I would really appreciate any correction of my current implementation as i am still fairly new into smart contract development.

# I wrote a test script for every function to observe the functions behavior (which **mr Patrick**) recommended as the industry standard. i wrote my test using foundry which is also another amazing tool.

# My aim is to get pretty good pretty quickly to be able to get a job and may God help me.

# The Contract code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Hodl is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error UnAuthorized();
    error Hodl__LockNotMature();
    error Hodl__NoBalance();
    error Hodl__EthTransferFailed();
    error Hodl__AmountExpected();
    error Hodl__DepositsPaused();
    error Hodl__WithdrawalsPaused();
    error Hodl__UnAuthorized();

    uint256 private constant SECONDS_PER_DAY = 24 * 60 * 60;

    address private constant NATIVE_TOKEN = address(0);
    ///@notice reason for the name admin is i can only pause and unpause deposit and withdrawals incase of an emergency. i don't have access to pamper with user funds
    address private admin;

    ///@notice this is done incase of an emergency event that we may need to pause the deposits and withdrawals
    bool private pauseDeposits = false;
    bool private pauseWithdrawals = false;

    mapping(address depositor => mapping(address token => uint256 amount))
        private deposits;
    mapping(address depositor => mapping(address token => uint256 unlockTime))
        private unlockTime;
    mapping(address depositor => address[] token) private userTokens;
    mapping(address depositor => mapping(address token => bool condition))
        private hasToken;

    event Withdrawal(address user, address token, uint256 balance);
    event Deposit(
        address user,
        address token,
        uint256 balance,
        uint256 lockPeriod
    );

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function _onlyAdmin() internal view {
        if (msg.sender != admin) revert Hodl__UnAuthorized();
    }

    /// @notice Deposit native ETH and lock it for a specified period
    /// @param lockPeriod The lock duration in days
    /// @dev Reverts if no ETH sent
    /// Emits a {Deposit} event
    function depositNativeEth(uint256 lockPeriod) public payable nonReentrant {
        address msgSender = msg.sender;
        uint256 amount = msg.value;
        setDeposit(msgSender, NATIVE_TOKEN, amount, lockPeriod);
        emit Deposit(msgSender, NATIVE_TOKEN, amount, lockPeriod);
    }

    /// @notice Deposit ERC20 tokens and lock them for a specified period
    /// @param token The ERC20 token address
    /// @param amount The amount of tokens to deposit
    /// @param lockPeriod The lock duration in days
    /// @dev Uses SafeERC20 for safe transfer, reverts if amount is zero
    /// Emits a {Deposit} event
    function depositErc20(
        address token,
        uint256 amount,
        uint256 lockPeriod
    ) external nonReentrant {
        address _msgSender = msg.sender;
        IERC20(token).safeTransferFrom(_msgSender, address(this), amount);
        setDeposit(_msgSender, token, amount, lockPeriod);
        emit Deposit(_msgSender, token, amount, lockPeriod);
    }

    /// @notice Withdraw deposited tokens or ETH after lock period matures
    /// @param token The token address to withdraw, NATIVE_TOKEN for native ETH
    /// @dev Reverts if balance is zero or lock period not mature
    /// Emits a {Withdrawal} event
    function withdraw(address token) external nonReentrant {
        if (pauseWithdrawals) revert Hodl__WithdrawalsPaused();

        address _msgSender = msg.sender;
        uint256 balance = getBalance(_msgSender, token);

        // --- Checks ---
        if (balance == 0) revert Hodl__NoBalance();

        uint256 lock = getLock(_msgSender, token);

        if (lock > 0 && !canWithdraw(msg.sender, token)) {
            revert Hodl__LockNotMature();
        }

        // --- Effects (update state first) ---
        deposits[_msgSender][token] = 0;
        unlockTime[_msgSender][token] = 0; // Clear unlock time after withdrawal
        address[] storage tokens = userTokens[_msgSender];

        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == token) {
                tokens[i] = tokens[tokens.length - 1];
                tokens.pop();
                hasToken[_msgSender][token] = false; // Update the mapping here
                break;
            }
        }

        // --- Interactions (do transfers last) ---
        if (token == NATIVE_TOKEN) {
            (bool success, ) = _msgSender.call{value: balance}("");
            if (!success) revert Hodl__EthTransferFailed();
        } else {
            IERC20(token).safeTransfer(_msgSender, balance);
        }

        emit Withdrawal(_msgSender, token, balance);
    }

    /// @notice Receive function to accept native ETH with zero lock period, why? because sender can immediately withdraw their asset incase this was unintentional
    receive() external payable {
        depositNativeEth(0);
    }

    /// @notice Fallback function to accept native ETH with zero lock period, why? because sender can immediately withdraw their asset incase this was unintentional
    fallback() external payable {
        depositNativeEth(0);
    }

    /// @notice Check if the unlock timestamp has passed
    /// @param unlockTimestamp The timestamp to check
    /// @return True if the current time is greater than or equal to unlockTimestamp
    function lockMaturity(
        uint256 unlockTimestamp
    ) internal view returns (bool) {
        return block.timestamp >= unlockTimestamp;
    }

    /// @notice Check if a user can withdraw a token based on unlock time
    /// @param user The address of the depositor
    /// @param token The token address
    /// @return True if withdrawal is allowed
    function canWithdraw(
        address user,
        address token
    ) internal view returns (bool) {
        uint256 userUnlockTime = unlockTime[user][token];
        return lockMaturity(userUnlockTime);
    }

    /// @notice Convert days to seconds
    /// @param days_ Number of days
    /// @return Equivalent seconds
    function daysToSeconds(uint256 days_) internal pure returns (uint256) {
        return days_ * SECONDS_PER_DAY;
    }

    /// @notice Get balance of a user for a specific token
    /// @param msgSender The user address
    /// @param token The token address
    /// @return amount The balance deposited
    function getBalance(
        address msgSender,
        address token
    ) internal view returns (uint256 amount) {
        amount = deposits[msgSender][token];
    }

    /// @notice Get all tokens, balances, and lock times for a user
    /// @param user The user address
    /// @return tokens Array of token addresses
    /// @return amounts Array of balances per token
    /// @return lock Array of unlock timestamps per token
    function getUserBalances(
        address user
    )
        external
        view
        returns (
            address[] memory tokens,
            uint256[] memory amounts,
            uint256[] memory lock
        )
    {
        uint256 length = userTokens[user].length;
        tokens = new address[](length);
        amounts = new uint256[](length);
        lock = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            address token = userTokens[user][i];
            tokens[i] = token;
            amounts[i] = deposits[user][token];
            lock[i] = unlockTime[user][token];
        }
    }

    /// @notice Get the unlock timestamp for a user's token deposit
    /// @param msgSender The user address
    /// @param token The token address
    /// @return lock Unlock timestamp
    function getLock(
        address msgSender,
        address token
    ) internal view returns (uint256 lock) {
        lock = unlockTime[msgSender][token];
    }

    //@notice a getter for pauseDeposits state
    function getDepositState() external view returns (bool) {
        return pauseDeposits;
    }

    //@notice a getter for pauseWithdrawals state
    function getWithdrawalState() external view returns (bool) {
        return pauseWithdrawals;
    }

    ///@notice function returns the current admin address
    function getAdmin() external view returns (address) {
        return admin;
    }

    /// @notice Internal function to set deposit and lock times for user tokens
    /// @param msgSender The user address
    /// @param token The token address
    /// @param amount Amount to deposit
    /// @param lockPeriod Lock duration in days
    function setDeposit(
        address msgSender,
        address token,
        uint256 amount,
        uint256 lockPeriod
    ) internal {
        if (pauseDeposits) revert Hodl__DepositsPaused();
        if (amount == 0) revert Hodl__AmountExpected();

        uint256 balance = getBalance(msgSender, token);
        uint256 lockInSeconds = daysToSeconds(lockPeriod);

        if (!hasToken[msgSender][token]) {
            userTokens[msgSender].push(token);
            hasToken[msgSender][token] = true;
        }

        deposits[msgSender][token] += amount;

        if (balance == 0) {
            // First time deposit: set unlockTime to now + lockPeriod
            unlockTime[msgSender][token] = block.timestamp + lockInSeconds;
        } else {
            // If current unlockTime is in the future, extend from there, else from now
            uint256 currentUnlock = unlockTime[msgSender][token];
            uint256 baseTime = currentUnlock > block.timestamp
                ? currentUnlock
                : block.timestamp;

            unlockTime[msgSender][token] = baseTime + lockInSeconds;
        }
    }

    /**@notice external function that changes the administrator of this contract
     * @notice onlyAdmin modifier checks if message sender != admin
     * @param newAdmin the address of the new administrator
     */
    function changeAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
    }

    /**
     * @notice function toggle the deposit state from true to false and otherwise
     * this function an only be called by the contract admin
     */
    function changeDepositState() external onlyAdmin {
        pauseDeposits = !pauseDeposits;
    }

    /**
     * @notice function toggle the withdrawal state from true to false and otherwise
     * this function an only be called by the contract admin
     */
    function changeWithdrawalState() external onlyAdmin {
        pauseWithdrawals = !pauseWithdrawals;
    }
}
```

# Foundry deploy script

```solidity
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

```

# for the tests i copied `Hodl.sol` code into `HodlTestFile.sol` and changed the functions visibility to public (because i don' now how to use internal and private functions inside the test file) so i won't let that slow me down. but every single functionality inside `Hodl.sol` is same content inside `HodlTestFile.sol`.

```solidity
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
        assertEq(
            hodl.SECONDS_PER_DAY(),
            86400,
            "SECONDS_PER_DAY should equal 86400"
        );
    }

    function testDepositNativeEth_Success() public {
        uint256 lockPeriod = 5; // days
        uint256 depositAmount = 0.5 ether;

        // Expect the Deposit event to be emitted
        vm.expectEmit(true, true, false, true);
        emit HodlTestFile.Deposit(
            user,
            NATIVE_TOKEN,
            depositAmount,
            lockPeriod
        );

        // Prank as the user and deposit ETH
        vm.prank(user);
        hodl.depositNativeEth{value: depositAmount}(lockPeriod);

        // Verify stored balance
        uint256 storedBalance = hodl.getBalance(user, NATIVE_TOKEN);
        console2.log(storedBalance);
        assertEq(storedBalance, depositAmount, "Balance not stored correctly");

        // Verify unlock time is correct
        uint256 storedUnlockTime = hodl.getLock(user, NATIVE_TOKEN);
        uint256 expectedUnlockTime = block.timestamp +
            hodl.daysToSeconds(lockPeriod);
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
        emit HodlTestFile.Deposit(
            user,
            address(mockToken),
            depositAmount,
            lockPeriod
        );

        // Call depositErc20
        hodl.depositErc20(address(mockToken), depositAmount, lockPeriod);
        vm.stopPrank();

        // --- Assertions ---
        assertEq(
            hodl.getBalance(user, address(mockToken)),
            depositAmount,
            "ERC20 balance mismatch"
        );

        uint256 expectedUnlock = block.timestamp +
            hodl.daysToSeconds(lockPeriod);
        assertEq(
            hodl.getLock(user, address(mockToken)),
            expectedUnlock,
            "Unlock time mismatch"
        );

        assertEq(
            mockToken.balanceOf(address(hodl)),
            depositAmount,
            "HodlTestFile contract did not receive tokens"
        );
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
        assertEq(
            hodl.getBalance(address(this), address(mockToken)),
            0,
            "Balance not reset"
        );

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
        (bool success, ) = address(hodl).call{value: 1 ether}("");
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
        hodl.depositErc20(
            address(mockToken),
            erc20DepositAmount,
            erc20LockPeriod
        );
        vm.stopPrank();

        // ----- Call getUserBalances -----
        (
            address[] memory tokens,
            uint256[] memory amounts,
            uint256[] memory locks
        ) = hodl.getUserBalances(user);

        // ----- Assertions -----
        assertEq(tokens.length, 2, "Token array length mismatch");
        assertEq(amounts.length, 2, "Amounts array length mismatch");
        assertEq(locks.length, 2, "Locks array length mismatch");

        // Check ETH deposit entry
        assertEq(tokens[0], NATIVE_TOKEN, "ETH token address mismatch");
        assertEq(amounts[0], ethDepositAmount, "ETH amount mismatch");
        assertEq(
            locks[0],
            block.timestamp + hodl.daysToSeconds(ethLockPeriod),
            "ETH lock time mismatch"
        );

        // Check ERC20 deposit entry
        assertEq(tokens[1], address(mockToken), "ERC20 token address mismatch");
        assertEq(amounts[1], erc20DepositAmount, "ERC20 amount mismatch");
        assertEq(
            locks[1],
            block.timestamp + hodl.daysToSeconds(erc20LockPeriod),
            "ERC20 lock time mismatch"
        );
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

        uint256 expectedUnlock = block.timestamp +
            hodl.daysToSeconds(lockPeriod);
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
```


# Add this variables to your **.env** file

    1. ETHERSCAN_KEY="replace with your etherscan api key" -> etherscan api key for automatic smart contract verification
   
    2. S_URL="replace with your rpc url" -> sepolia rpc url

    3. T_KEY="replace with your developer private dev" -> your dev private key (security warning) don't use your private key with real funds
 
    4. ANVIL_RPC= "http://127.0.0.1:8545" -> ANVIL DEFAULT RPC URL

    5. A_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" -> ANVIL DUMMY PRIVATE KEY


# To run the project, you will need:

    1. Foundry
    2. openzeppelin-contracts

    initialize a foundry project command: forge init
    install openzeppelin command: forge install @openzeppelin/openzeppelin-contracts

    test command: make t
    deploy to local anvil chain command: make a-dep
    deploy to sepolia testnet command: make s-dep
