// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SavingsVault} from "../../src/SavingsVault.sol";

contract DepositorActor {
    SavingsVault private immutable vault;
    bool private callbackAttempted;

    constructor(SavingsVault target) payable {
        vault = target;
    }

    function exerciseWithdrawal() external {
        vault.deposit{value: 1 ether}();
        vault.withdraw(1 ether);
    }

    receive() external payable {
        if (!callbackAttempted) {
            callbackAttempted = true;
            try vault.withdraw(1 ether) {} catch {}
        }
    }
}

contract TrustedSafetyTest {
    function test_Safety_WithdrawalEntitlement() public {
        SavingsVault vault = new SavingsVault();
        vault.deposit{value: 2 ether}();
        DepositorActor actor = new DepositorActor{value: 1 ether}(vault);
        actor.exerciseWithdrawal();
        require(address(actor).balance <= 1 ether, "audit: safety violation");
        require(address(vault).balance >= 2 ether, "audit: safety violation");
    }
}

