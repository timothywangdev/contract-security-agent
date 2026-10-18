// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ReentrancyVault} from "../src/ReentrancyVault.sol";
import {FeeManager} from "../src/FeeManager.sol";
import {ShareVault} from "../src/ShareVault.sol";

contract NormalTest {
    receive() external payable {}

    function test_ReentrancyVaultDepositAndWithdraw() public {
        ReentrancyVault vault = new ReentrancyVault();
        uint256 initial = address(this).balance;
        vault.deposit{value: 1 ether}();
        require(vault.credits(address(this)) == 1 ether, "deposit credit");
        vault.withdraw(1 ether);
        require(vault.credits(address(this)) == 0, "withdrawal credit");
        require(address(this).balance == initial, "legitimate payout");
    }

    function test_ReentrancyVaultEmptyAccountCannotWithdraw() public {
        ReentrancyVault vault = new ReentrancyVault();
        (bool success,) = address(vault).call(abi.encodeCall(vault.withdraw, (1 ether)));
        require(!success, "empty account withdrawal");
    }

    function test_FeeManagerOwnerCanPause() public {
        FeeManager fm = new FeeManager(address(0xBEEF));
        fm.pause();
        require(fm.paused(), "owner pause");
    }

    function test_FeeManagerNonOwnerCannotPause() public {
        FeeManager fm = new FeeManager(address(0xBEEF));
        Caller caller = new Caller();
        bool success = caller.callPause(fm);
        require(!success, "non-owner pause");
    }

    function test_ShareVaultDepositAndWithdraw() public {
        ShareVault vault = new ShareVault();
        uint256 initial = address(this).balance;
        vault.deposit{value: 1 ether}();
        require(vault.shares(address(this)) == 1 ether, "initial shares");
        vault.withdraw(1 ether);
        require(vault.shares(address(this)) == 0, "shares burned");
        require(address(this).balance == initial, "legitimate payout");
    }
}

contract Caller {
    function callPause(FeeManager fm) external returns (bool success) {
        (success,) = address(fm).call(abi.encodeCall(fm.pause, ()));
    }
}
