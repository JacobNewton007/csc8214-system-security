// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Crowdfunding.sol";

/// @notice Test-only beneficiary that re-enters withdraw() while being paid.
/// @dev The try/catch swallows the expected AlreadyWithdrawn revert so that the
///      outer payment still succeeds and the test can assert on the outcome.
contract ReentrantBeneficiary {
    Crowdfunding public campaign;
    uint256 public reentryAttempts;
    bool public reentrySucceeded;
    uint256 public amountReceived;

    function setCampaign(Crowdfunding _campaign) external {
        campaign = _campaign;
    }

    receive() external payable {
        amountReceived += msg.value;
        if (address(campaign) != address(0) && reentryAttempts == 0) {
            reentryAttempts += 1;
            try campaign.withdraw() {
                reentrySucceeded = true;
            } catch {
                reentrySucceeded = false;
            }
        }
    }

    function sweep(address payable to) external {
        to.transfer(address(this).balance);
    }
}
