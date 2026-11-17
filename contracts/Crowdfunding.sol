// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * CSC8214 System Security - Assignment Question B.4
 *
 * A minimal crowdfunding contract.
 *
 * Requirements from the question, and where each one is met:
 *   1. accept contributions                   -> contribute()
 *   2. record a beneficiary address and a
 *      funding target                         -> `beneficiary` and `target`,
 *                                                both set once in the constructor
 *                                                and declared `immutable`
 *   3. release funds only to the beneficiary
 *      once the target has been reached       -> withdraw(), guarded by
 *                                                onlyBeneficiary and by the
 *                                                `totalRaised >= target` check
 *   4. prevent the same funds being withdrawn
 *      twice                                  -> the `withdrawn` flag, which is
 *                                                set BEFORE the transfer
 *                                                (checks-effects-interactions)
 */
contract Crowdfunding {
    // ---------------------------------------------------------------------
    // STATE
    // ---------------------------------------------------------------------

    /// The only address that may ever receive the raised funds.
    /// `immutable` means it is fixed at deployment and cannot be rewritten
    /// afterwards, not even by the deployer. That removes a whole class of
    /// "owner changes the payout address" attacks.
    address payable public immutable beneficiary;

    /// The funding target, in wei. Also fixed at deployment so that nobody can
    /// lower the bar once contributions have started arriving.
    uint256 public immutable target;

    /// Total contributed so far, in wei. Tracked explicitly rather than read
    /// from address(this).balance, because the balance can be inflated by a
    /// selfdestruct from another contract, which would otherwise let the
    /// campaign "reach" its target without a single genuine contribution.
    uint256 public totalRaised;

    /// Per-contributor totals. Kept for transparency and because any refund
    /// mechanism added later (see Question B.5) would need it.
    mapping(address => uint256) public contributions;

    /// REQUIREMENT 4: the one-shot latch that makes withdrawal non-repeatable.
    bool public withdrawn;

    // ---------------------------------------------------------------------
    // EVENTS - the cheap, off-chain-readable audit trail
    // ---------------------------------------------------------------------

    event ContributionReceived(address indexed contributor, uint256 amount, uint256 totalRaised);
    event TargetReached(uint256 totalRaised);
    event FundsWithdrawn(address indexed beneficiary, uint256 amount);

    // ---------------------------------------------------------------------
    // ERRORS - custom errors are cheaper than revert strings
    // ---------------------------------------------------------------------

    error ZeroContribution();
    error NotBeneficiary(address caller);
    error TargetNotReached(uint256 raised, uint256 required);
    error AlreadyWithdrawn();
    error TransferFailed();

    // ---------------------------------------------------------------------
    // CONSTRUCTOR - REQUIREMENT 2: record the beneficiary and the target
    // ---------------------------------------------------------------------

    constructor(address payable _beneficiary, uint256 _target) {
        // Validate once, at deployment. A zero beneficiary would burn the funds
        // and a zero target would make the campaign succeed before it started.
        require(_beneficiary != address(0), "beneficiary must not be the zero address");
        require(_target > 0, "target must be greater than zero");
        beneficiary = _beneficiary;
        target = _target;
    }

    // ---------------------------------------------------------------------
    // MODIFIER
    // ---------------------------------------------------------------------

    /// Access control for the withdrawal path. `msg.sender` is set by the EVM
    /// itself, so it cannot be spoofed by the caller.
    modifier onlyBeneficiary() {
        if (msg.sender != beneficiary) revert NotBeneficiary(msg.sender);
        _;
    }

    // ---------------------------------------------------------------------
    // REQUIREMENT 1: accept contributions
    // ---------------------------------------------------------------------

    /**
     * Contribute ether to the campaign.
     *
     * Deliberately still accepted after the target is reached: over-funding a
     * campaign is normal, and rejecting late contributions would mean a
     * contributor could lose gas to a revert through no fault of their own.
     */
    function contribute() public payable {
        if (msg.value == 0) revert ZeroContribution();

        // EFFECTS. Solidity >= 0.8 reverts automatically on overflow, so these
        // additions need no SafeMath.
        bool wasBelowTarget = totalRaised < target;
        contributions[msg.sender] += msg.value;
        totalRaised += msg.value;

        emit ContributionReceived(msg.sender, msg.value, totalRaised);

        // Emit TargetReached exactly once, on the contribution that crosses it.
        if (wasBelowTarget && totalRaised >= target) {
            emit TargetReached(totalRaised);
        }
    }

    /// Accept plain transfers (no calldata) as contributions too, so that a
    /// contributor who sends ether straight to the address is not silently
    /// ignored or, worse, has the funds trapped.
    receive() external payable {
        contribute();
    }

    // ---------------------------------------------------------------------
    // REQUIREMENTS 3 and 4: release funds to the beneficiary, exactly once
    // ---------------------------------------------------------------------

    /**
     * Withdraw the raised funds to the beneficiary.
     *
     * Written in checks-effects-interactions order, which is what makes the
     * double-withdrawal and reentrancy protection sound:
     *
     *   CHECKS       caller is the beneficiary; the target has been reached;
     *                the funds have not been withdrawn already.
     *   EFFECTS      set `withdrawn = true` BEFORE any external call. If the
     *                beneficiary is a contract whose receive() calls back into
     *                withdraw(), the re-entrant call hits `AlreadyWithdrawn`
     *                and reverts, so the funds can never leave twice.
     *   INTERACTION  send the ether last.
     */
    function withdraw() external onlyBeneficiary {
        // CHECK: REQUIREMENT 3 - nothing is released below the target.
        if (totalRaised < target) revert TargetNotReached(totalRaised, target);
        // CHECK: REQUIREMENT 4 - one withdrawal only, ever.
        if (withdrawn) revert AlreadyWithdrawn();

        // EFFECT: flip the latch first. This single line is the double-spend
        // defence; everything after it is already protected by it.
        withdrawn = true;

        uint256 amount = address(this).balance;

        // INTERACTION: `call` forwards all remaining gas, which is the
        // recommended way to pay an address that may be a contract (transfer()
        // and send() cap the gas at 2300 and break on such beneficiaries).
        // Because the latch is already set, forwarding gas is safe here.
        (bool ok, ) = beneficiary.call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit FundsWithdrawn(beneficiary, amount);
    }

    // ---------------------------------------------------------------------
    // VIEWS - read-only helpers, free to call off-chain
    // ---------------------------------------------------------------------

    /// True once the campaign has met or exceeded its target.
    function targetReached() external view returns (bool) {
        return totalRaised >= target;
    }

    /// How much more is needed, in wei (0 once the target is met).
    function remaining() external view returns (uint256) {
        return totalRaised >= target ? 0 : target - totalRaised;
    }

    /// The ether currently held by the contract.
    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}
