// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract SavingsVault {
    mapping(address => uint256) public credits;

    function deposit() external payable {
        credits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(credits[msg.sender] >= amount, "insufficient credit");
        credits[msg.sender] -= amount;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
    }
}

