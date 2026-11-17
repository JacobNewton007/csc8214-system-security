// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Crowdfunding campaign with a fixed beneficiary and funding target.
/// @notice Accepts contributions and releases the balance to the beneficiary
///         once, and only once the target has been reached.
contract Crowdfunding {
    /// @dev Immutable, so the payout address cannot be changed after deployment.
    address payable public immutable beneficiary;
    uint256 public immutable target;

    /// @dev Tracked separately from address(this).balance, which selfdestruct
    ///      can inflate without a genuine contribution.
    uint256 public totalRaised;

    mapping(address => uint256) public contributions;

    /// @dev One-shot latch: the defence against a second withdrawal.
    bool public withdrawn;

    event ContributionReceived(address indexed contributor, uint256 amount, uint256 totalRaised);
    event TargetReached(uint256 totalRaised);
    event FundsWithdrawn(address indexed beneficiary, uint256 amount);

    error ZeroContribution();
    error NotBeneficiary(address caller);
    error TargetNotReached(uint256 raised, uint256 required);
    error AlreadyWithdrawn();
    error TransferFailed();

    modifier onlyBeneficiary() {
        if (msg.sender != beneficiary) revert NotBeneficiary(msg.sender);
        _;
    }

    constructor(address payable _beneficiary, uint256 _target) {
        require(_beneficiary != address(0), "beneficiary must not be the zero address");
        require(_target > 0, "target must be greater than zero");
        beneficiary = _beneficiary;
        target = _target;
    }

    /// @notice Contribute to the campaign.
    /// @dev Accepted after the target is reached too, so that a late
    ///      contributor does not lose gas to a revert.
    function contribute() public payable {
        if (msg.value == 0) revert ZeroContribution();

        bool wasBelowTarget = totalRaised < target;
        contributions[msg.sender] += msg.value;
        totalRaised += msg.value;

        emit ContributionReceived(msg.sender, msg.value, totalRaised);
        if (wasBelowTarget && totalRaised >= target) emit TargetReached(totalRaised);
    }

    /// @notice Treat a plain transfer as a contribution rather than trapping it.
    receive() external payable {
        contribute();
    }

    /// @notice Release the balance to the beneficiary.
    /// @dev Checks-effects-interactions: `withdrawn` is set before the external
    ///      call, so a re-entrant call reverts with AlreadyWithdrawn.
    function withdraw() external onlyBeneficiary {
        if (totalRaised < target) revert TargetNotReached(totalRaised, target);
        if (withdrawn) revert AlreadyWithdrawn();

        withdrawn = true;
        uint256 amount = address(this).balance;

        // `call` rather than transfer(), whose 2300 gas stipend breaks
        // contract beneficiaries. Safe here because the latch is already set.
        (bool ok, ) = beneficiary.call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit FundsWithdrawn(beneficiary, amount);
    }

    function targetReached() external view returns (bool) {
        return totalRaised >= target;
    }

    function remaining() external view returns (uint256) {
        return totalRaised >= target ? 0 : target - totalRaised;
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
