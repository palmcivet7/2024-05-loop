// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {Handler} from "./Handler.t.sol";
import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {PrelaunchPoints} from "../../src/PrelaunchPoints.sol";
import {ILpETH} from "../../src/interfaces/ILpETH.sol";
import {ILpETHVault} from "../../src/interfaces/ILpETHVault.sol";
import {LRToken} from "../../src/mock/MockLRT.sol";
import {MockLpETH} from "../../src/mock/MockLpETH.sol";
import {MockLpETHVault} from "../../src/mock/MockLpETHVault.sol";

contract Invariant is StdInvariant, Test {
    Handler handler;
    PrelaunchPoints plp;
    address deployer = makeAddr("deployer");

    ILpETH public lpETH;
    LRToken public lrt;
    ILpETHVault public lpETHVault;

    address constant EXCHANGE_PROXY = 0xDef1C0ded9bec7F1a1670819833240f027b25EfF;
    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address[] public allowedTokens;
    uint256 public constant INITIAL_SUPPLY = 1000 ether;

    constructor() {
        vm.startPrank(deployer);
        lrt = new LRToken();
        lrt.mint(deployer, INITIAL_SUPPLY);
        address[] storage allowedTokens_ = allowedTokens;
        allowedTokens_.push(address(lrt));
        plp = new PrelaunchPoints(EXCHANGE_PROXY, WETH, allowedTokens_);
        lpETH = new MockLpETH();
        lpETHVault = new MockLpETHVault();
        vm.stopPrank();

        handler = new Handler(plp, deployer, address(this), lpETH, lrt, lpETHVault);

        bytes4[] memory selectors = new bytes4[](9);

        selectors[0] = Handler.lockETH.selector;
        selectors[1] = Handler.lockETHFor.selector;
        selectors[2] = Handler.lock.selector;
        selectors[3] = Handler.lockFor.selector;
        selectors[4] = Handler.claim.selector;
        selectors[5] = Handler.claimAndStake.selector;
        selectors[6] = Handler.withdraw.selector;

        // ------ Authorized -------
        selectors[7] = Handler.setLoopAddresses.selector;
        selectors[8] = Handler.convertAllETH.selector;
        // selectors[9] = Handler.setOwner.selector;
        // selectors[10] = Handler.setEmergencyMode.selector;
        // selectors[11] = Handler.allowToken.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    // Only the owner can set new accepted LRTs, change mode to emergency mode on failure of 0x integration, and set a new owner

    // function invariant_onlyOwner_can_set_new_LRTs() public {}

    function invariant_onlyOwner_can_change_to_emergency_mode_on_0x_failure() public {
        assertEq(handler.g_emergencyMode(), plp.emergencyMode());
    }

    function invariant_onlyOwner_can_set_a_new_owner() public {
        assertEq(plp.owner(), handler.owner());
    }

    function invariant_onlyOwner_can_set_loop_addresses() public {
        assertEq(address(plp.lpETH()), address(handler.lpETH()));
        assertEq(address(plp.lpETHVault()), address(handler.lpETHVault()));
    }

    // Deposits are active up to the lpETH contract and lpETHVault contract are set

    function invariant_deposits_are_active_until_loop_addresses_set() public {}

    // Withdrawals are only active on emergency mode or during 7 days after loopActivation is set

    function invariant_withdraws_are_conditionally_active() public {
        if (!handler.g_emergencyMode() && block.timestamp > handler.g_loopAddressesSetTime() + 7 days) {
            assertEq(handler.g_totalWithdraws(), 0);
        }
    }

    // Users that deposit ETH/WETH get the correct amount of lpETH on claim (1 to 1 conversion)

    function invariant_lpETH_claims_are_correct() public {}

    // Users that deposit LRTs get the correct amount assuming a favorable swap to ETH

    function invariant_LRTs_swaps_are_correct() public {}

    function invariant_correct_handling_of_deposits() public {
        assertEq(plp.totalSupply(), handler.g_totalEthDeposits());
    }

    function invariant_correct_claim_amounts() public {
        uint256 numDepositors = handler.getNumDepositors(); // You may need to implement this method to return length of the EnumerableSet
        for (uint256 i = 0; i < numDepositors; i++) {
            address depositor = handler.getDepositorAt(i); // Adjust this to use the EnumerableSet `at` function
            uint256 expected = handler.g_depositorToAmountClaimed(depositor);
            uint256 actual = lpETH.balanceOf(depositor);
            assertEq(actual, expected);
        }
    }

    function invariant_token_allowance_consistency() public {
        uint256 numTokens = handler.getNumAllowedTokens(); // Similarly, implement this to return the number of tokens in the EnumerableSet
        for (uint256 i = 0; i < numTokens; i++) {
            address token = handler.getAllowedTokenAt(i); // Use the EnumerableSet `at` function to access the token
            assertEq(plp.isTokenAllowed(token), handler.g_allowedTokens(token));
        }
    }
}
