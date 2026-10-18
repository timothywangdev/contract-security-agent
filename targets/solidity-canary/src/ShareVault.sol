// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// Bug: first-depositor share-price manipulation. `receive()` lets anyone
/// send ETH directly to the contract, inflating `address(this).balance`
/// without minting shares. An attacker who holds the first (tiny) share can
/// donate a large amount directly, rounding a subsequent depositor down to
/// zero minted shares, then withdraw the victim's deposit as their own.
contract ShareVault {
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit() external payable returns (uint256 minted) {
        if (totalShares == 0) {
            minted = msg.value;
        } else {
            minted = (msg.value * totalShares) / (address(this).balance - msg.value);
        }
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function withdraw(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "insufficient shares");
        uint256 amount = (shareAmount * address(this).balance) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
    }

    receive() external payable {}
}
