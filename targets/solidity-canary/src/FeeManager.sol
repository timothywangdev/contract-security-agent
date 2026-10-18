// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// Bug: `setFeeRecipient` has no access-control check — any caller can
/// redirect protocol fees to an address of their choosing. `pause` is
/// correctly restricted to `owner`, for contrast.
contract FeeManager {
    address public owner;
    address public feeRecipient;
    bool public paused;

    constructor(address initialRecipient) {
        owner = msg.sender;
        feeRecipient = initialRecipient;
    }

    function setFeeRecipient(address newRecipient) external {
        feeRecipient = newRecipient;
    }

    function pause() external {
        require(msg.sender == owner, "not owner");
        paused = true;
    }
}
