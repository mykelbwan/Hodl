// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract HodlTestFile is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error UnAuthorized();
    error Hodl__LockNotMature();
    error Hodl__NoBalance();
    error Hodl__EthTransferFailed();
    error Hodl__AmountExpected();
    error Hodl__DepositsPaused();
    error Hodl__WithdrawalsPaused();
    error Hodl__UnAuthorized();

    uint256 public constant SECONDS_PER_DAY = 24 * 60 * 60;

    address private constant NATIVE_TOKEN = address(0);
    ///@notice reason for the name admin is i can only pause and unpause deposit and withdrawals incase of an emergency. i don't have access to pamper with user funds
    address private admin;

    ///@notice this is done incase of an emergency event that we may need to pause the deposits and withdrawals
    bool private pauseDeposits = false;
    bool private pauseWithdrawals = false;

    mapping(address depositor => mapping(address token => uint256 amount)) private deposits;
    mapping(address depositor => mapping(address token => uint256 unlockTime)) private unlockTime;
    mapping(address depositor => address[] tokenList) private userTokens;
    mapping(address depositor => mapping(address token => bool condition)) private hasToken;

    event Withdrawal(address user, address token, uint256 balance);
    event Deposit(address user, address token, uint256 balance, uint256 lockPeriod);

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
    function depositErc20(address token, uint256 amount, uint256 lockPeriod) external nonReentrant {
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
            (bool success,) = _msgSender.call{value: balance}("");
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
    function lockMaturity(uint256 unlockTimestamp) public view returns (bool) {
        return block.timestamp >= unlockTimestamp;
    }

    /// @notice Check if a user can withdraw a token based on unlock time
    /// @param user The address of the depositor
    /// @param token The token address
    /// @return True if withdrawal is allowed
    function canWithdraw(address user, address token) public view returns (bool) {
        uint256 userUnlockTime = unlockTime[user][token];
        return lockMaturity(userUnlockTime);
    }

    /// @notice Convert days to seconds
    /// @param days_ Number of days
    /// @return Equivalent seconds
    function daysToSeconds(uint256 days_) public pure returns (uint256) {
        return days_ * SECONDS_PER_DAY;
    }

    /// @notice Get balance of a user for a specific token
    /// @param msgSender The user address
    /// @param token The token address
    /// @return amount The balance deposited
    function getBalance(address msgSender, address token) public view returns (uint256 amount) {
        amount = deposits[msgSender][token];
    }

    /// @notice Get all tokens, balances, and lock times for a user
    /// @param user The user address
    /// @return tokens Array of token addresses
    /// @return amounts Array of balances per token
    /// @return lock Array of unlock timestamps per token
    function getUserBalances(address user)
        external
        view
        returns (address[] memory tokens, uint256[] memory amounts, uint256[] memory lock)
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
    function getLock(address msgSender, address token) public view returns (uint256 lock) {
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

    function getAdmin() external view returns (address) {
        return admin;
    }

    /// @notice Internal function to set deposit and lock times for user tokens
    /// @param msgSender The user address
    /// @param token The token address
    /// @param amount Amount to deposit
    /// @param lockPeriod Lock duration in days
    function setDeposit(address msgSender, address token, uint256 amount, uint256 lockPeriod) public {
        if (pauseDeposits) revert Hodl__DepositsPaused();
        if (amount == 0) revert Hodl__AmountExpected();

        uint256 balance = getBalance(msgSender, token);
        uint256 lockInSeconds = daysToSeconds(lockPeriod);

        if (!hasToken[msgSender][token]) {
            userTokens[msgSender].push(token);
            hasToken[msgSender][token] = true;
        }

        deposits[msgSender][token] += amount; // add balance once here

        if (balance == 0) {
            // First time deposit: set unlockTime to now + lockPeriod
            unlockTime[msgSender][token] = block.timestamp + lockInSeconds;
        } else {
            // If current unlockTime is in the future, extend from there, else from now
            uint256 currentUnlock = unlockTime[msgSender][token];
            uint256 baseTime = currentUnlock > block.timestamp ? currentUnlock : block.timestamp;

            unlockTime[msgSender][token] = baseTime + lockInSeconds;
        }
    }

    /**
     * @notice external function that changes the administrator of this contract
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

    /**
     * @notice this functions are only for test purposes
     */
    function getUserTokens(address user) public view returns (address[] memory) {
        return userTokens[user];
    }

    function setUnlockTime(address user, address token, uint256 lockPeriod) public {
        uint256 lockInSeconds = daysToSeconds(lockPeriod);

        uint256 currentUnlock = unlockTime[user][token];
        uint256 baseTime = currentUnlock > block.timestamp ? currentUnlock : block.timestamp;

        unlockTime[user][token] = baseTime + lockInSeconds;
    }
}
