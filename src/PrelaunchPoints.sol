// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import {ILpETH, IERC20} from "./interfaces/ILpETH.sol";
import {ILpETHVault} from "./interfaces/ILpETHVault.sol";
import {IWETH} from "./interfaces/IWETH.sol";
import {console} from "forge-std/Test.sol";

/**
 * @title   PrelaunchPoints
 * @author  Loop
 * @notice  Staking points contract for the prelaunch of Loop Protocol.
 */
contract PrelaunchPoints {
    using Math for uint256;
    using SafeERC20 for IERC20;
    using SafeERC20 for ILpETH;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    ILpETH public lpETH;
    ILpETHVault public lpETHVault;
    IWETH public immutable WETH;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    // q what is exchangeProxy?
    // a it is the address of the 0x ExchangeProxy
    // https://etherscan.io/address/0xdef1c0ded9bec7f1a1670819833240f027b25eff#code
    address public immutable exchangeProxy;

    address public owner;

    uint256 public totalSupply;
    uint256 public totalLpETH;
    mapping(address => bool) public isTokenAllowed;

    enum Exchange {
        UniswapV3,
        TransformERC20
    }

    bytes4 public constant UNI_SELECTOR = 0x803ba26d;
    // transformERC20(address,address,uint256,uint256,(uint32,bytes)[])
    bytes4 public constant TRANSFORM_SELECTOR = 0x415565b0;

    uint32 public loopActivation;
    // e startClaimDate gets set in convertAllETH by owner
    // users cannot withdraw ETH or LRT after this, they can only claim lpETH
    uint32 public startClaimDate;
    uint32 public constant TIMELOCK = 7 days;
    bool public emergencyMode;

    mapping(address => mapping(address => uint256)) public balances; // User -> Token -> Balance

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Locked(address indexed user, uint256 amount, address token, bytes32 indexed referral);
    event StakedVault(address indexed user, uint256 amount);
    event Converted(uint256 amountETH, uint256 amountlpETH);
    event Withdrawn(address indexed user, address token, uint256 amount);
    event Claimed(address indexed user, address token, uint256 reward);
    event Recovered(address token, uint256 amount);
    event OwnerUpdated(address newOwner);
    event LoopAddressesUpdated(address loopAddress, address vaultAddress);
    event SwappedTokens(address sellToken, uint256 sellAmount, uint256 buyETHAmount);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidToken();
    error NothingToClaim();
    error TokenNotAllowed();
    error CannotLockZero();
    error CannotWithdrawZero();
    error UseClaimInstead();
    error FailedToSendEther();
    error SwapCallFailed();
    error WrongSelector(bytes4 selector);
    error WrongDataTokens(address inputToken, address outputToken);
    error WrongDataAmount(uint256 inputTokenAmount);
    error WrongRecipient(address recipient);
    error WrongExchange();
    error LoopNotActivated();
    error NotValidToken();
    error NotAuthorized();
    error CurrentlyNotPossible();
    error NoLongerPossible();

    /*//////////////////////////////////////////////////////////////
                             INITIALIZATION
    //////////////////////////////////////////////////////////////*/
    /**
     * @param _exchangeProxy address of the 0x protocol exchange proxy
     * @param _wethAddress   address of WETH
     * @param _allowedTokens list of token addresses to allow for locking
     */
    constructor(address _exchangeProxy, address _wethAddress, address[] memory _allowedTokens) {
        owner = msg.sender;
        exchangeProxy = _exchangeProxy;
        WETH = IWETH(_wethAddress);

        loopActivation = uint32(block.timestamp + 120 days);
        startClaimDate = 4294967295; // Max uint32 ~ year 2107

        // Allow intital list of tokens
        uint256 length = _allowedTokens.length;
        for (uint256 i = 0; i < length;) {
            isTokenAllowed[_allowedTokens[i]] = true;
            unchecked {
                i++;
            }
        }
        isTokenAllowed[_wethAddress] = true;
    }

    /*//////////////////////////////////////////////////////////////
                            STAKE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Locks ETH
     * @param _referral  info of the referral. This value will be processed in the backend.
     */
    function lockETH(bytes32 _referral) external payable {
        _processLock(ETH, msg.value, msg.sender, _referral);
    }

    /**
     * @notice Locks ETH for a given address
     * @param _for       address for which ETH is locked
     * @param _referral  info of the referral. This value will be processed in the backend.
     */
    function lockETHFor(address _for, bytes32 _referral) external payable {
        _processLock(ETH, msg.value, _for, _referral);
    }

    /**
     * @notice Locks a valid token
     * @param _token     address of token to lock
     * @param _amount    amount of token to lock
     * @param _referral  info of the referral. This value will be processed in the backend.
     */
    function lock(address _token, uint256 _amount, bytes32 _referral) external {
        if (_token == ETH) {
            revert InvalidToken();
        }
        _processLock(_token, _amount, msg.sender, _referral);
    }

    /**
     * @notice Locks a valid token for a given address
     * @param _token     address of token to lock
     * @param _amount    amount of token to lock
     * @param _for       address for which ETH is locked
     * @param _referral  info of the referral. This value will be processed in the backend.
     */
    function lockFor(address _token, uint256 _amount, address _for, bytes32 _referral) external {
        if (_token == ETH) {
            revert InvalidToken();
        }
        _processLock(_token, _amount, _for, _referral);
    }

    /**
     * @dev Generic internal locking function that updates rewards based on
     *      previous balances, then update balances.
     * @param _token       Address of the token to lock
     * @param _amount      Units of ETH or token to add to the users balance
     * @param _receiver    Address of user who will receive the stake
     * @param _referral    Address of the referral user
     */
    function _processLock(address _token, uint256 _amount, address _receiver, bytes32 _referral)
        internal
        onlyBeforeDate(loopActivation)
    {
        // @audit-followup reentrancy
        /**
         *     Reentrancy in PrelaunchPoints._processLock(address,uint256,address,bytes32) (src/PrelaunchPoints.sol#172-198):
         *     External calls:
         *     - IERC20(_token).safeTransferFrom(msg.sender,address(this),_amount) (src/PrelaunchPoints.sol#186)
         *     - WETH.withdraw(_amount) (src/PrelaunchPoints.sol#189)
         *     State variables written after the call(s):
         *     - balances[_receiver][ETH] += _amount (src/PrelaunchPoints.sol#191)
         *     - totalSupply = totalSupply + _amount (src/PrelaunchPoints.sol#190)
         * Reentrancy in PrelaunchPoints._processLock(address,uint256,address,bytes32) (src/PrelaunchPoints.sol#172-198):
         *     External calls:
         *     - IERC20(_token).safeTransferFrom(msg.sender,address(this),_amount) (src/PrelaunchPoints.sol#186)
         *     State variables written after the call(s):
         *     - balances[_receiver][_token] += _amount (src/PrelaunchPoints.sol#193)
         */
        if (_amount == 0) {
            revert CannotLockZero();
        }
        if (_token == ETH) {
            totalSupply = totalSupply + _amount;
            balances[_receiver][ETH] += _amount;
        } else {
            if (!isTokenAllowed[_token]) {
                revert TokenNotAllowed();
            }
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);

            if (_token == address(WETH)) {
                WETH.withdraw(_amount); // coverage
                totalSupply = totalSupply + _amount; // coverage
                balances[_receiver][ETH] += _amount; // coverage
            } else {
                // @audit-followup, so we're tracking the totalSupply for ETH but not other tokens?
                balances[_receiver][_token] += _amount;
            }
        }

        emit Locked(_receiver, _amount, _token, _referral);
    }

    /*//////////////////////////////////////////////////////////////
                        CLAIM AND WITHDRAW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Called by a user to get their vested lpETH
     * @param _token      Address of the token to convert to lpETH
     * @param _percentage Proportion in % of tokens to withdraw. NOT useful for ETH
     * @param _exchange   Exchange identifier where the swap takes place
     * @param _data       Swap data obtained from 0x API
     */
    // q what is Exchange?
    // a enum - UniswapV3 or TransformERC20
    function claim(address _token, uint8 _percentage, Exchange _exchange, bytes calldata _data)
        external
        onlyAfterDate(startClaimDate)
    {
        _claim(_token, msg.sender, _percentage, _exchange, _data);
    }

    /**
     * @dev Called by a user to get their vested lpETH and stake them in a
     *      Loop vault for extra rewards
     * @param _token      Address of the token to convert to lpETH
     * @param _percentage Proportion in % of tokens to withdraw. NOT useful for ETH
     * @param _exchange   Exchange identifier where the swap takes place
     * @param _data       Swap data obtained from 0x API
     */
    function claimAndStake(address _token, uint8 _percentage, Exchange _exchange, bytes calldata _data)
        external
        onlyAfterDate(startClaimDate)
    {
        uint256 claimedAmount = _claim(_token, address(this), _percentage, _exchange, _data);
        // @audit-followup ignores return value
        // https://solodit.xyz/issues/m-02-unchecked-low-level-calls-code4rena-boot-finance-boot-finance-contest-git
        // https://github.com/crytic/slither/wiki/Detector-Documentation#unused-return
        lpETH.approve(address(lpETHVault), claimedAmount);
        lpETHVault.stake(claimedAmount, msg.sender);

        emit StakedVault(msg.sender, claimedAmount);
    }

    /**
     * @dev Claim logic. If necessary converts token to ETH before depositing into lpETH contract.
     */
    function _claim(address _token, address _receiver, uint8 _percentage, Exchange _exchange, bytes calldata _data)
        internal
        returns (uint256 claimedAmount)
    {
        // console.log("xxxxxxxxxx THIS LINE IS HIT xxxxxxxxxx");
        uint256 userStake = balances[msg.sender][_token];
        if (userStake == 0) {
            revert NothingToClaim();
        }
        if (_token == ETH) {
            // coverage
            claimedAmount = userStake.mulDiv(totalLpETH, totalSupply);
            balances[msg.sender][_token] = 0;
            lpETH.safeTransfer(_receiver, claimedAmount);
        } else {
            // console.log("-----------THIS LINE IS HIT-------------");
            uint256 userClaim = userStake * _percentage / 100;
            console.log("User Stake:", userStake);
            console.log("Percentage:", _percentage);
            console.log("Calculated Claim:", userClaim);
            _validateData(_token, userClaim, _exchange, _data); // coverage
            balances[msg.sender][_token] = userStake - userClaim; // coverage

            // At this point there should not be any ETH in the contract
            // Swap token to ETH
            console.log("ETH Balance before swap:", address(this).balance);
            _fillQuote(IERC20(_token), userClaim, _data);
            console.log("ETH Balance after swap:", address(this).balance);
            console.log("Attempting to deposit ETH to lpETH:", claimedAmount);

            // Convert swapped ETH to lpETH (1 to 1 conversion)
            claimedAmount = address(this).balance; // coverage
            lpETH.deposit{value: claimedAmount}(_receiver);
        }
        emit Claimed(msg.sender, _token, claimedAmount);
    }

    /**
     * @dev Called by a staker to withdraw all their ETH or LRT
     * Note Can only be called after the loop address is set and before claiming lpETH,
     * i.e. for at least TIMELOCK. In emergency mode can be called at any time.
     * @param _token      Address of the token to withdraw
     */
    function withdraw(address _token) external {
        if (!emergencyMode) {
            if (block.timestamp <= loopActivation) {
                revert CurrentlyNotPossible();
            }
            if (block.timestamp >= startClaimDate) {
                revert NoLongerPossible();
            }
        }

        uint256 lockedAmount = balances[msg.sender][_token];
        balances[msg.sender][_token] = 0;

        if (lockedAmount == 0) {
            // coverage
            revert CannotWithdrawZero();
        }
        if (_token == ETH) {
            if (block.timestamp >= startClaimDate) {
                revert UseClaimInstead(); // coverage
            }
            totalSupply = totalSupply - lockedAmount;

            (bool sent,) = msg.sender.call{value: lockedAmount}("");

            if (!sent) {
                revert FailedToSendEther();
            }
        } else {
            IERC20(_token).safeTransfer(msg.sender, lockedAmount);
        }

        emit Withdrawn(msg.sender, _token, lockedAmount);
    }

    /*//////////////////////////////////////////////////////////////
                            PROTECTED FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Called by a owner to convert all the locked ETH to get lpETH
     */
    function convertAllETH() external onlyAuthorized onlyBeforeDate(startClaimDate) {
        if (block.timestamp - loopActivation <= TIMELOCK) {
            revert LoopNotActivated();
        }

        // deposits all the ETH to lpETH contract. Receives lpETH back
        uint256 totalBalance = address(this).balance;
        lpETH.deposit{value: totalBalance}(address(this));

        // q what happens if lpETH are sent to address(this) directly?
        // a nothing, it just gets included and cant be retrieved by the sender
        totalLpETH = lpETH.balanceOf(address(this));

        // Claims of lpETH can start immediately after conversion.
        startClaimDate = uint32(block.timestamp);

        emit Converted(totalBalance, totalLpETH);
    }

    /**
     * @notice Sets a new owner
     * @param _owner address of the new owner
     */
    function setOwner(address _owner) external onlyAuthorized {
        owner = _owner;

        emit OwnerUpdated(_owner);
    }

    /**
     * @notice Sets the lpETH contract address
     * @param _loopAddress address of the lpETH contract
     * @dev Can only be set once before 120 days have passed from deployment.
     *      After that users can only withdraw ETH.
     */
    function setLoopAddresses(address _loopAddress, address _vaultAddress)
        external
        onlyAuthorized
        onlyBeforeDate(loopActivation)
    {
        lpETH = ILpETH(_loopAddress);
        lpETHVault = ILpETHVault(_vaultAddress);
        loopActivation = uint32(block.timestamp);

        emit LoopAddressesUpdated(_loopAddress, _vaultAddress);
    }

    /**
     * @param _token address of a wrapped LRT token
     * @dev ONLY add wrapped LRT tokens. Contract not compatible with rebase tokens.
     */
    function allowToken(address _token) external onlyAuthorized {
        isTokenAllowed[_token] = true;
    }

    /**
     * @param _mode boolean to activate/deactivate the emergency mode
     * @dev On emergency mode all withdrawals are accepted at
     */
    function setEmergencyMode(bool _mode) external onlyAuthorized {
        emergencyMode = _mode;
    }

    /**
     * @dev Allows the owner to recover other ERC20s mistakingly sent to this contract
     */
    function recoverERC20(address tokenAddress, uint256 tokenAmount) external onlyAuthorized {
        if (tokenAddress == address(lpETH) || isTokenAllowed[tokenAddress]) {
            revert NotValidToken();
        }
        IERC20(tokenAddress).safeTransfer(owner, tokenAmount);

        emit Recovered(tokenAddress, tokenAmount);
    }

    /**
     * Enable receive ETH
     * @dev ETH sent to this contract directly will be locked forever.
     */
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validates the data sent from 0x API to match desired behaviour
     * @param _token     address of the token to sell
     * @param _amount    amount of token to sell
     * @param _exchange  exchange identifier where the swap takes place
     * @param _data      swap data from 0x API
     */
    function _validateData(address _token, uint256 _amount, Exchange _exchange, bytes calldata _data) internal view {
        address inputToken;
        address outputToken;
        uint256 inputTokenAmount; // coverage
        address recipient;
        bytes4 selector;

        if (_exchange == Exchange.UniswapV3) {
            // coverage
            (inputToken, outputToken, inputTokenAmount, recipient, selector) = _decodeUniswapV3Data(_data); // coverage
            if (selector != UNI_SELECTOR) {
                revert WrongSelector(selector);
            }
            // UniswapV3Feature.sellTokenForEthToUniswapV3(encodedPath, sellAmount, minBuyAmount, recipient) requires `encodedPath` to be a Uniswap-encoded path, where the last token is WETH, and sends the NATIVE token to `recipient`
            if (outputToken != address(WETH)) {
                // coverage
                revert WrongDataTokens(inputToken, outputToken);
            }
        } else if (_exchange == Exchange.TransformERC20) {
            (inputToken, outputToken, inputTokenAmount, selector) = _decodeTransformERC20Data(_data);
            if (selector != TRANSFORM_SELECTOR) {
                revert WrongSelector(selector);
            }
            if (outputToken != ETH) {
                //coverage
                revert WrongDataTokens(inputToken, outputToken);
            }
        } else {
            revert WrongExchange();
        }

        if (inputToken != _token) {
            // coverage
            revert WrongDataTokens(inputToken, outputToken);
        }
        if (inputTokenAmount != _amount) {
            revert WrongDataAmount(inputTokenAmount);
        }
        if (recipient != address(this) && recipient != address(0)) {
            revert WrongRecipient(recipient); // coverage
        }
    }

    /**
     * @notice Decodes the data sent from 0x API when UniswapV3 is used
     * @param _data      swap data from 0x API
     */
    function _decodeUniswapV3Data(bytes calldata _data)
        internal
        pure
        returns (address inputToken, address outputToken, uint256 inputTokenAmount, address recipient, bytes4 selector)
    {
        uint256 encodedPathLength;
        assembly {
            let p := _data.offset
            selector := calldataload(p)
            p := add(p, 36) // Data: selector 4 + lenght data 32 // coverage
            inputTokenAmount := calldataload(p)
            recipient := calldataload(add(p, 64))
            encodedPathLength := calldataload(add(p, 96)) // Get length of encodedPath (obtained through abi.encodePacked) // coverage
            inputToken := shr(96, calldataload(add(p, 128))) // Shift to the Right with 24 zeroes (12 bytes = 96 bits) to get address
            outputToken := shr(96, calldataload(add(p, add(encodedPathLength, 108)))) // Get last address of the hop
        }
    }

    /**
     * @notice Decodes the data sent from 0x API when other exchanges are used via 0x TransformERC20 function
     * @param _data      swap data from 0x API
     */
    function _decodeTransformERC20Data(
        bytes calldata _data // coverage
    ) internal pure returns (address inputToken, address outputToken, uint256 inputTokenAmount, bytes4 selector) {
        assembly {
            let p := _data.offset
            selector := calldataload(p) // coverage
            inputToken := calldataload(add(p, 4)) // Read slot, selector 4 bytes
            outputToken := calldataload(add(p, 36)) // Read slot
            inputTokenAmount := calldataload(add(p, 68)) // Read slot // coverage
        }
    }

    /**
     *
     * @param _sellToken     The `sellTokenAddress` field from the API response.
     * @param _amount       The `sellAmount` field from the API response.
     * @param _swapCallData  The `data` field from the API response.
     */
    function _fillQuote(IERC20 _sellToken, uint256 _amount, bytes calldata _swapCallData) internal {
        // coverage
        // Track our balance of the buyToken to determine how much we've bought.
        uint256 boughtETHAmount = address(this).balance; // coverage

        console.log("Approved amount for swap:", _sellToken.allowance(address(this), exchangeProxy));
        require(_sellToken.approve(exchangeProxy, _amount));

        // q what is happening here?
        // a _swapCallData is sent to 0x protocol's Zero Exchange contract which then makes a swap with
        //   either Uniswap or TransformERC20
        (bool success,) = payable(exchangeProxy).call{value: 0}(_swapCallData); // coverage
        if (!success) {
            revert SwapCallFailed(); // coverage
        }

        // Use our current buyToken balance to determine how much we've bought.
        boughtETHAmount = address(this).balance - boughtETHAmount; // coverage
        emit SwappedTokens(address(_sellToken), _amount, boughtETHAmount);
    }

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyAuthorized() {
        if (msg.sender != owner) {
            revert NotAuthorized();
        }
        _;
    }

    modifier onlyAfterDate(uint256 limitDate) {
        if (block.timestamp <= limitDate) {
            revert CurrentlyNotPossible();
        }
        _;
    }

    modifier onlyBeforeDate(uint256 limitDate) {
        //coverage
        if (block.timestamp >= limitDate) {
            revert NoLongerPossible();
        }
        _;
    }
}
