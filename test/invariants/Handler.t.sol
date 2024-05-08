// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {PrelaunchPoints} from "../../src/PrelaunchPoints.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ILpETH} from "../../src/interfaces/ILpETH.sol";
import {ILpETHVault} from "../../src/interfaces/ILpETHVault.sol";
import {LRToken} from "../../src/mock/MockLRT.sol";

contract Handler is Test {
    using EnumerableSet for EnumerableSet.AddressSet;

    PrelaunchPoints public plp;
    address public owner;
    address invariant;

    ILpETH public lpETH;
    LRToken public lrt;
    ILpETHVault public lpETHVault;

    uint256 public constant ONE_MILLION_TOKENS = 1_000_000 ether;
    bytes4 public constant UNI_SELECTOR = 0x803ba26d;
    bytes4 public constant TRANSFORM_SELECTOR = 0x415565b0;

    enum Exchange {
        UniswapV3,
        TransformERC20
    }

    /// ghost variables
    bool public g_loopAddressesSet;
    mapping(address => bool) public g_allowedTokens;
    bool public g_emergencyMode;
    mapping(address => uint256) public g_depositorToEthAmount;
    uint256 public g_totalEthDeposits;
    mapping(address => mapping(address => uint256)) public g_depositorToTokenToAmount;
    mapping(address => uint256) public g_tokenToTotalDeposits;
    bool public g_ethConvertedToLpEth;
    uint256 public g_totalLpEth;
    uint256 public g_currentTime;
    uint256 public g_loopAddressesSetTime;
    mapping(address => uint256) public g_depositorToAmountClaimed;
    uint256 public g_startClaimDate;
    uint256 public g_totalWithdraws;

    EnumerableSet.AddressSet internal e_lrtTokens;
    EnumerableSet.AddressSet internal e_depositors;
    EnumerableSet.AddressSet internal e_allowedTokens;
    EnumerableSet.AddressSet internal e_claimers;

    constructor(
        PrelaunchPoints _plp,
        address _owner,
        address _invariant,
        ILpETH _lpETH,
        LRToken _lrt,
        ILpETHVault _lpETHVault
    ) {
        plp = _plp;
        owner = _owner;
        invariant = _invariant;
        lpETH = _lpETH;
        lrt = _lrt;
        lpETHVault = _lpETHVault;
        e_lrtTokens.add(address(_lrt));
        g_currentTime = block.timestamp;
        e_allowedTokens.add(address(_lrt));
    }

    function setOwner(uint256 _addressSeed, uint256 _addressSeed2) public returns (address) {
        address user = _seedToAddress(_addressSeed);
        address newOwner = _seedToAddress(_addressSeed2);
        if (user != owner) {
            vm.expectRevert();
            vm.prank(user);
            plp.setOwner(newOwner);
            return owner;
        } else if (user == owner) {
            vm.prank(user);
            plp.setOwner(newOwner);
            owner = newOwner;
            return newOwner;
        }
    }

    function setLoopAddresses(uint256 _addressSeed, address _owner) public returns (bool) {
        if (g_loopAddressesSet) return true;
        if (_owner == owner) {
            vm.prank(owner);
            plp.setLoopAddresses(address(lpETH), address(lpETHVault));
            g_loopAddressesSet = true;
            g_loopAddressesSetTime = block.timestamp;
            return true;
        }
        address user = _seedToAddress(_addressSeed);
        if (user != owner) {
            vm.expectRevert();
            vm.prank(user);
            plp.setLoopAddresses(address(lpETH), address(lpETHVault));
            g_loopAddressesSet = false;
            return false;
        } else if (user == owner) {
            vm.prank(user);
            plp.setLoopAddresses(address(lpETH), address(lpETHVault));
            g_loopAddressesSet = true;
            g_loopAddressesSetTime = block.timestamp;
            return true;
        }
    }

    function allowToken(uint256 _addressSeed, uint256 _addressSeed2) public returns (address, bool) {
        address user = _seedToAddress(_addressSeed);
        address newLrtToken = _seedToAddress(_addressSeed2);
        if (user != owner) {
            vm.expectRevert();
            vm.prank(user);
            plp.allowToken(newLrtToken);
            return (newLrtToken, g_allowedTokens[newLrtToken]);
        } else if (user == owner) {
            vm.prank(user);
            plp.allowToken(newLrtToken);

            g_allowedTokens[newLrtToken] = true;
            e_lrtTokens.add(newLrtToken);

            return (newLrtToken, g_allowedTokens[newLrtToken]);
        }
    }

    function setEmergencyMode(uint256 _addressSeed, bool _mode) public returns (bool) {
        address user = _seedToAddress(_addressSeed);
        if (user != owner) {
            vm.expectRevert();
            vm.prank(user);
            plp.setEmergencyMode(_mode);
            return false;
        } else if (user == owner) {
            vm.prank(user);
            plp.setEmergencyMode(_mode);

            g_emergencyMode = _mode;

            return g_emergencyMode;
        }
    }

    function convertAllETH(uint256 _owner, uint256 _addressSeed) public {
        if (g_ethConvertedToLpEth) {
            _warpTime();
            return;
        }
        if (g_currentTime <= g_loopAddressesSetTime + 7 days) {
            _warpTime();
            return;
        }

        address caller = _seedToAddress(_addressSeed);

        if (_owner % 5 == 0) {
            vm.prank(owner);
            plp.convertAllETH();

            g_totalLpEth += g_totalEthDeposits;
            g_ethConvertedToLpEth = true;
            g_totalEthDeposits = 0;
            assertGt(g_totalLpEth, g_totalEthDeposits);
            g_startClaimDate = block.timestamp;
        } else {
            vm.prank(caller);
            vm.expectRevert();
            plp.convertAllETH();
        }
    }

    function lockETH(uint256 _addressSeed, uint256 _amount, bytes32 _referral)
        public
        returns (address depositor, uint256 depositedAmount)
    {
        depositor = _seedToAddress(_addressSeed);

        depositedAmount = bound(_amount, 1, ONE_MILLION_TOKENS);

        if (g_loopAddressesSet) {
            vm.deal(depositor, depositedAmount);
            vm.prank(depositor);
            vm.expectRevert();
            plp.lockETH{value: depositedAmount}(_referral);

            _warpTime();
        } else if (!g_loopAddressesSet) {
            vm.deal(depositor, depositedAmount);
            vm.prank(depositor);
            plp.lockETH{value: depositedAmount}(_referral);

            // g_depositorToEthAmount[depositor] += depositedAmount;
            g_totalEthDeposits += depositedAmount;
            address eth_address = plp.ETH();
            g_depositorToTokenToAmount[depositor][eth_address] = depositedAmount;
            g_tokenToTotalDeposits[eth_address] += depositedAmount;
            e_depositors.add(depositor);
        }
    }

    function lockETHFor(uint256 _addressSeed, uint256 _addressSeed2, uint256 _amount, bytes32 _referral)
        public
        returns (address depositor, uint256 depositedAmount)
    {
        address sender = _seedToAddress(_addressSeed);
        depositor = _seedToAddress(_addressSeed2);
        depositedAmount = bound(_amount, 1, ONE_MILLION_TOKENS);

        if (g_loopAddressesSet) {
            vm.deal(sender, depositedAmount);
            vm.prank(sender);
            vm.expectRevert();
            plp.lockETHFor{value: depositedAmount}(depositor, _referral);

            _warpTime();
        } else if (!g_loopAddressesSet) {
            vm.deal(sender, depositedAmount);
            vm.prank(sender);
            plp.lockETHFor{value: depositedAmount}(depositor, _referral);

            // g_depositorToEthAmount[depositor] += depositedAmount;
            g_totalEthDeposits += depositedAmount;
            address eth_address = plp.ETH();
            g_depositorToTokenToAmount[depositor][eth_address] = depositedAmount;
            g_tokenToTotalDeposits[eth_address] += depositedAmount;
            e_depositors.add(depositor);
        }
    }

    function lock(uint256 _addressSeed, uint256 _addressSeed2, uint256 _amount, bytes32 _referral)
        public
        returns (address depositor, address tokenAddress, uint256 depositedAmount)
    {
        depositor = _seedToAddress(_addressSeed);
        tokenAddress = _indexToLrtTokenAddress(_addressSeed2);

        LRToken newLrt = LRToken(tokenAddress);
        depositedAmount = bound(_amount, 1, ONE_MILLION_TOKENS);
        newLrt.mint(depositor, depositedAmount);

        if (g_loopAddressesSet) {
            vm.startPrank(depositor);
            newLrt.approve(address(plp), depositedAmount);
            vm.expectRevert();
            plp.lock(tokenAddress, depositedAmount, _referral);
            vm.stopPrank();

            _warpTime();
        } else if (!g_loopAddressesSet) {
            vm.startPrank(depositor);
            newLrt.approve(address(plp), depositedAmount);
            plp.lock(tokenAddress, depositedAmount, _referral);
            vm.stopPrank();

            g_depositorToTokenToAmount[depositor][tokenAddress] = depositedAmount;
            g_tokenToTotalDeposits[tokenAddress] += depositedAmount;
            e_depositors.add(depositor);
        }
    }

    function lockFor(
        uint256 _addressSeed,
        uint256 _addressSeed2,
        uint256 _addressSeed3,
        uint256 _amount,
        bytes32 _referral
    ) public returns (address depositor, address tokenAddress, uint256 depositedAmount) {
        address sender = _seedToAddress(_addressSeed);
        depositor = _seedToAddress(_addressSeed2);
        tokenAddress = _indexToLrtTokenAddress(_addressSeed3);

        LRToken newLrt = LRToken(tokenAddress);
        depositedAmount = bound(_amount, 1, ONE_MILLION_TOKENS);
        newLrt.mint(sender, depositedAmount);

        if (g_loopAddressesSet) {
            vm.startPrank(sender);
            newLrt.approve(address(plp), depositedAmount);
            vm.expectRevert();
            plp.lockFor(tokenAddress, depositedAmount, depositor, _referral);
            vm.stopPrank();

            _warpTime();
        } else if (!g_loopAddressesSet) {
            vm.startPrank(sender);
            newLrt.approve(address(plp), depositedAmount);
            plp.lockFor(tokenAddress, depositedAmount, depositor, _referral);
            vm.stopPrank();

            g_depositorToTokenToAmount[depositor][tokenAddress] = depositedAmount;
            g_tokenToTotalDeposits[tokenAddress] += depositedAmount;
            e_depositors.add(depositor);
        }
    }

    //// why is claim reverting???

    function claim(uint256 _addressSeed, uint256 _addressSeed2, uint256 _percentage, PrelaunchPoints.Exchange _exchange)
        public
    {
        // onlyAfterDate(startDate)
        if (g_startClaimDate > block.timestamp) {
            _warpTime();
            return;
        }

        // seed to depositor
        address user = _indexToDepositorAddress(_addressSeed);
        // seed to token
        address token = _indexToAllowedTokenAddress(_addressSeed2);
        if (g_depositorToTokenToAmount[user][token] == 0) token = _indexToAllowedTokenAddress(_addressSeed2 % 2);
        if (g_depositorToTokenToAmount[user][token] == 0) token = _indexToAllowedTokenAddress(_addressSeed2 % 3);
        uint256 depositedAmount = g_depositorToTokenToAmount[user][token];

        _percentage = bound(_percentage, 1, 100);

        bytes4 selector;
        if (_exchange == PrelaunchPoints.Exchange.UniswapV3) {
            selector = UNI_SELECTOR;
        } else {
            selector = TRANSFORM_SELECTOR;
        }

        bytes memory data = abi.encodeWithSelector(selector, token, plp.WETH(), depositedAmount, user);

        vm.prank(user);
        plp.claim(token, uint8(_percentage), _exchange, data);

        uint256 percentageClaimed = depositedAmount * _percentage / 100;
        g_depositorToAmountClaimed[user] = percentageClaimed;
        e_claimers.add(user);
    }

    function claimAndStake(
        uint256 _addressSeed,
        uint256 _addressSeed2,
        uint256 _percentage,
        PrelaunchPoints.Exchange _exchange
    ) public {
        // onlyAfterDate(startDate)
        if (g_startClaimDate > block.timestamp) {
            _warpTime();
            return;
        }

        // seed to depositor
        address user = _indexToDepositorAddress(_addressSeed);
        // seed to token
        address token = _indexToAllowedTokenAddress(_addressSeed2);
        if (g_depositorToTokenToAmount[user][token] == 0) token = _indexToAllowedTokenAddress(_addressSeed2 % 2);
        if (g_depositorToTokenToAmount[user][token] == 0) token = _indexToAllowedTokenAddress(_addressSeed2 % 3);
        uint256 depositedAmount = g_depositorToTokenToAmount[user][token];
        if (depositedAmount == 0) return; // or call another func

        uint256 actualDepositedAmount = plp.balances(user, token);
        assertEq(actualDepositedAmount, depositedAmount);

        _percentage = bound(_percentage, 1, 100);

        bytes4 selector;
        if (_exchange == PrelaunchPoints.Exchange.UniswapV3) {
            selector = UNI_SELECTOR;
        } else {
            selector = TRANSFORM_SELECTOR;
        }

        bytes memory data = abi.encodeWithSelector(selector, token, plp.WETH(), depositedAmount, user);

        vm.prank(user);
        plp.claimAndStake(token, uint8(_percentage), _exchange, data);

        uint256 percentageClaimed = depositedAmount * _percentage / 100;
        g_depositorToAmountClaimed[user] = percentageClaimed;
        e_claimers.add(user);
    }

    function withdraw(uint256 _addressSeed, uint256 _addressSeed2) public {
        address user = _indexToDepositorAddress(_addressSeed);
        address token = _indexToAllowedTokenAddress(_addressSeed2);
        if (g_depositorToTokenToAmount[user][token] == 0) token = _indexToAllowedTokenAddress(_addressSeed2 % 2);
        if (g_depositorToTokenToAmount[user][token] == 0) token = _indexToAllowedTokenAddress(_addressSeed2 % 3);
        uint256 ghostDepositedAmount = g_depositorToTokenToAmount[user][token];
        if (ghostDepositedAmount == 0) return; // or call another func

        if (!g_emergencyMode) {
            if (g_currentTime <= g_loopAddressesSetTime) {
                _warpTime();
                return;
            }
            if (g_currentTime >= g_startClaimDate) {
                return;
            }
        }

        uint256 actualDepositedAmount = plp.balances(user, token);
        assertEq(actualDepositedAmount, ghostDepositedAmount);

        vm.prank(user);
        plp.withdraw(token);

        g_totalWithdraws += ghostDepositedAmount;
        g_tokenToTotalDeposits[token] -= ghostDepositedAmount;
        g_depositorToTokenToAmount[user][token] = 0;
    }

    /**
     * ------ Authorized -------
     * recoverERC20()
     */

    /*//////////////////////////////////////////////////////////////
                                 GETTER
    //////////////////////////////////////////////////////////////*/
    // Accessor for depositor addresses using EnumerableSet
    function getNumDepositors() public view returns (uint256) {
        return e_depositors.length(); // Assuming `depositors` is an EnumerableSet.AddressSet
    }

    function getDepositorAt(uint256 index) public view returns (address) {
        return e_depositors.at(index); // Assuming `depositors` is an EnumerableSet.AddressSet
    }

    // Accessor for allowed token addresses using EnumerableSet
    function getNumAllowedTokens() public view returns (uint256) {
        return e_allowedTokens.length(); // Assuming `allowedTokens` is an EnumerableSet.AddressSet
    }

    function getAllowedTokenAt(uint256 index) public view returns (address) {
        return e_allowedTokens.at(index); // Assuming `allowedTokens` is an EnumerableSet.AddressSet
    }

    /*//////////////////////////////////////////////////////////////
                                 UTILS
    //////////////////////////////////////////////////////////////*/
    /// @dev Convert a seed to an address
    function _seedToAddress(uint256 addressSeed) internal pure returns (address) {
        return address(uint160(bound(addressSeed, 1, type(uint160).max)));
    }

    /// @dev Convert an index to an existing depositor address
    function _indexToDepositorAddress(uint256 addressIndex) internal view returns (address) {
        return e_depositors.at(bound(addressIndex, 0, e_depositors.length() - 1));
    }

    /// @dev Convert an index to an existing LRT Token address
    function _indexToLrtTokenAddress(uint256 addressIndex) internal view returns (address) {
        return e_lrtTokens.at(bound(addressIndex, 0, e_lrtTokens.length() - 1));
    }

    /// @dev Convert an index to an existing allowed token address
    function _indexToAllowedTokenAddress(uint256 addressIndex) internal view returns (address) {
        return e_allowedTokens.at(bound(addressIndex, 0, e_allowedTokens.length() - 1));
    }

    function _warpTime() internal {
        vm.warp(1 days);
        g_currentTime += 1 days;
    }
}
