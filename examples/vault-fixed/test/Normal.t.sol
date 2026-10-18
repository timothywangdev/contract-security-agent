// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SavingsVault} from "../src/SavingsVault.sol";

contract NormalTest {
    receive() external payable {}

    function test_DepositAndWithdrawal() public {
        SavingsVault vault = new SavingsVault();
        uint256 initial = address(this).balance;
        vault.deposit{value: 1 ether}();
        require(vault.credits(address(this)) == 1 ether, "deposit credit");
        vault.withdraw(1 ether);
        require(vault.credits(address(this)) == 0, "withdrawal credit");
        require(address(this).balance == initial, "legitimate payout");
    }

    function test_EmptyAccountCannotWithdraw() public {
        SavingsVault vault = new SavingsVault();
        (bool success,) = address(vault).call(abi.encodeCall(vault.withdraw, (1 ether)));
        require(!success, "empty account withdrawal");
    }
}

