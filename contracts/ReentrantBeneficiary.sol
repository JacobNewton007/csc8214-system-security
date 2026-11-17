// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Crowdfunding.sol";

/**
 * CSC8214 - a hostile beneficiary used only for testing.
 *
 * This contract is set as the campaign's beneficiary. When the Crowdfunding
 * contract pays it, its receive() function immediately calls withdraw() again,
 * which is the classic reentrancy pattern that drained The DAO in 2016.
 *
 * Because Crowdfunding.withdraw() sets `withdrawn = true` BEFORE sending the
 * ether (checks-effects-interactions), the re-entrant call reverts with
 * AlreadyWithdrawn. The try/catch here swallows that revert so that the outer
 * payment still succeeds, which makes the test show the real outcome: exactly
 * one payout, and `reentrySucceeded == false`.
 */
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
        // Attempt the re-entrant withdrawal exactly once.
        if (address(campaign) != address(0) && reentryAttempts == 0) {
            reentryAttempts += 1;
            try campaign.withdraw() {
                reentrySucceeded = true; // would mean the defence failed
            } catch {
                reentrySucceeded = false; // expected: AlreadyWithdrawn
            }
        }
    }

    /// Lets the test move the stolen/earned funds out, to prove it really has them.
    function sweep(address payable to) external {
        to.transfer(address(this).balance);
    }
}
