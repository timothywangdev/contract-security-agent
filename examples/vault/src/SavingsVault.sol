// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract SavingsVault {
    mapping(address => uint256) public credits;

    function deposit() external payable {
        credits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(credits[msg.sender] >= amount, "insufficient credit");
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
        unchecked {
            credits[msg.sender] -= amount;
        }
    }
}

