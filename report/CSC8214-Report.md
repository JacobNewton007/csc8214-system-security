# CSC8214 System Security: Assignment and Report

**Student number (ID):** `260452597`

All outputs quoted below were produced by `python3 psi/run_experiments.py` and
`npx hardhat run scripts/test_crowdfunding.js`, and are copied verbatim from
`results/transcript.txt` and `results/crowdfunding_tests.txt`. Source code is in Appendix A.

---

# Part A: Private Set Intersection

## A.1 Concept

Private Set Intersection (PSI) is a cryptographic protocol which, as Lecture 3 [1] puts it,
"lets mutually distrustful parties compute the intersection of their private sets such that
nothing about the sets' elements, beyond the result, is revealed". In its example, Alice holds
`{1, 2, 3}` and Bob `{1, 3, 4, 5, 9}`; both may learn `{1, 3}`, but Bob must not learn `2` and
Alice must not learn `4`, `5` or `9`.

Computing an intersection would be trivial if the parties could hand their sets to a trusted
third party. PSI is non-trivial precisely because no such party exists, and neither owner knows
what the other holds.

PSI protocols divide into two settings [1]. In **traditional PSI** the only participants are the
set owners, who interactively compute the result from their local sets and repeat that work
every time. In **delegated PSI** the owners encode their sets and send the encodings to a server, typically cloud, which performs the computation and/or storage on their behalf. Delegated
protocols divide further into **one-off delegation**, where the owners re-encode their data for
each computation, and **repeated delegation**, where one outsourcing supports any number of
later intersections. A.3's protocol is a delegated PSI with one-off delegation.

Security is stated against an adversary type [1]. A passive (semi-honest) adversary is the
weakest: it follows the protocol but is curious, so a PSI secure against it need only satisfy
privacy. An active (malicious) adversary is the strongest: it may deviate from the
protocol's instructions, so the PSI must additionally guarantee the result's correctness, in
the sense that deviation producing an incorrect result is detected. Common building blocks are
hash functions, pseudorandom functions (PRFs), homomorphic encryption and polynomial
representations for security, and hash tables and Bloom filters for efficiency.

## A.2 Application

A real-world application is Apple's proposed system to combat Child Sexual Abuse Material
(2021) [10, 11], which used PSI to check images on a user's device against a database of known illegal
images held by child-protection organisations.
The design is described by Bhowmick et al., *The Apple PSI System* (2021), covered in Lecture 4.

Plain data sharing fails in both directions. Uploading every user photo for checking would
concentrate the private photo library of every customer on one company's servers: a permanent
target for breach, insider abuse and legal compulsion, and an intrusion far wider than the
question being asked. Publishing the database to devices fails too: its entries
identify known illegal material, so anyone holding them could test candidate images and alter
whichever matched until they evaded detection.

An intersection is exactly the computation required, and nothing more. The question is
genuinely "which of this device's images appear in that database?", and neither side may see
the other's set. The design therefore ran the matching on the device against a blinded copy of
the database, so the device learned nothing about the database contents and Apple learned
nothing about the images that did not match. A threshold was applied so that no result was
revealed until a set number of matches had accumulated, limiting the damage from a single false
positive.

The example also shows PSI's limit. The protocol can guarantee that only the intersection is
revealed; it cannot decide whether computing that intersection is legitimate. Apple later dropped
the plan, in 2022, after sustained criticism that the same machinery, once deployed, could be
repointed at any other database. Cryptography constrained what was learned, not what could
later be asked.

## A.3 Protocol design

**Parties and inputs.** Client 1 holds `X₁ = {1, 2, 5, 9, ID}`; Client 2 holds
`X₂ = {5, 8, 11, ID}`, where `ID` is my student number. The Server has no input set. This is a
**delegated PSI** with one-off delegation: the clients encode their sets, the Server compares
them, and both clients learn `X₁ ∩ X₂` without sending any raw element.

**Threat model.** The Server is passive (semi-honest): it follows the protocol but is
curious. The protocol therefore aims at privacy only, not at detecting deviation.

**Primitive.** A cryptographic hash function `H = SHA-256`, with a fixed domain-separation tag
`T = "CSC8214-PSI-v1|"` and a fixed canonical encoding of elements. Both clients must use the
identical tag and encoding, or equal elements would hash differently and the intersection would
come out empty.

**Messages exchanged.**

| # | From → To | Message | Contents |
|---|---|---|---|
| 1 | C1 → S | `BLINDED_SET` | `D₁ = shuffle({ H(T‖x) : x ∈ X₁ })` |
| 2 | C2 → S | `BLINDED_SET` | `D₂ = shuffle({ H(T‖x) : x ∈ X₂ })` |
| 3 | S → C1, C2 | `INTERSECTION` | `I = D₁ ∩ D₂` (digests only) |

**Steps.**

1. **Blinding (each client, locally).** Client *i* hashes every element of its set and keeps a
   private lookup table `Tᵢ : digest ↦ element`. The table never leaves the client and is the
   only thing that can invert a digest.
2. **Submission.** Each client sends only the digests, in shuffled order. Shuffling matters:
   in set order, a digest's position would leak the ordering of the underlying elements.
3. **Intersection (Server).** The Server, holding no set of its own, computes `I = D₁ ∩ D₂` and
   returns `I` to both clients.
4. **Recovery (each client, locally).** Client *i* maps each digest in `I` back through `Tᵢ`.
   Because `H` is deterministic, a shared element yields an identical digest at both clients, so
   `I` holds exactly the digests of `X₁ ∩ X₂` and each client recovers it.

**Why no element reaches the Server.** The Server receives only 256-bit digests and returns a
subset of what it was given. A digest cannot be inverted by computation alone, only by guessing
candidate inputs and hashing them. A.5 shows that for this element domain guessing is entirely
practical, and fixes the gap.

## A.4 Implementation and testing

The protocol is implemented in Python 3 using the standard library only (Appendix A). Comments
marked `PROTOCOL STEP n` identify each step of A.3 in the code, with the optional key exchange
as Step 0. The Server logs every message it receives, and that log is reproduced below.

### (i) Run 1: the given sets

Client 1 = `{1, 2, 5, 9, ID}`, Client 2 = `{5, 8, 11, ID}`, `ID = 260452597`.

**Messages received by the Server** (session `run1`):

```
[ 1] Server <-- client2   BLINDED_SET   mode=plain  count=4
       7171a8e2f17b8501a55f4f943f528666e8137ba9515d910b4dc559d38af1135e
       d78bd3d40637d1b405728f69a29ca85976e5e7824f1033e8c46967fe01d4767f
       443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e
       ce21b7c354366862da6409a2087b7694374c3587843cfa0bd74e156213b05d41
[ 2] Server <-- client1   BLINDED_SET   mode=plain  count=5
       443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e
       99e2d08e26e0cf553853271a4d51fa24a533cc7cc262cdbdce98dd64901dddab
       96dcfae20d4e26466b1f7dace43d95372c97aeea149dfa30d7c16f0d2261b9ee
       ecf2de5604e9c6182e7216c895ec99794da0a8100ee978ef94492316155c67b0
       7171a8e2f17b8501a55f4f943f528666e8137ba9515d910b4dc559d38af1135e
[ 3] Server --> both clients   INTERSECTION   count=2
       443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e
       7171a8e2f17b8501a55f4f943f528666e8137ba9515d910b4dc559d38af1135e
```

No raw set element appears anywhere in the Server's view. Both clients run concurrently and
shuffle before sending, so the order of the messages and of the digests within them varies
between runs; the digests themselves, and the Server's answer, do not.

**Clients' outputs**

```
[client2] INTERSECTION = [5, 260452597]
[client1] INTERSECTION = [5, 260452597]
```

Each client inverted the two returned digests through its own table and obtained `{5, ID}`.

### (ii) Run 2: Client 2's set modified

Client 2's set was changed from `{5, 8, 11, ID}` to `{2, 8, 11, ID}`: the shared element `5` was
removed and `2`, which Client 1 holds, was added. Client 1's set was unchanged.

```
[client1] INTERSECTION = [2, 260452597]
[client2] INTERSECTION = [2, 260452597]
```

**Explanation.** The output changed from `{5, ID}` to `{2, ID}`, as the sets dictate. `5`
disappeared because Client 2 no longer holds it, so its digest `443d7581…` is now in `D₁` only
and fails the intersection. `2` appeared because both clients now hold it, so both produced the
identical digest `ecf2de56…` and it survived. `ID` remains common to both sets, so `7171a8e2…`
is returned again, and it is the same digest string as in Run 1.

## A.5 Privacy analysis

### What the Server can learn from the messages in A.4

Although no element is sent in the clear, the Server's view is not empty. It directly learns the
cardinality of each set (5 and 4), the size of the intersection (2), and, because
digests are deterministic and unkeyed, which digests the two clients share and which are
unique to one of them. Across sessions it learns more: digest `7171a8e2…` appears in Run 1, Run
2 and in both clients' sets, so the Server can link the same element across runs and across
clients without yet knowing what it is.

### Could the Server recover elements by hashing candidate values? Yes.

SHA-256 is public, unkeyed and deterministic, so the Server can compute it on any candidate and
compare. One-wayness is irrelevant here because the input domain is minuscule: small integers,
and a student number, which is not secret and follows a published nine-digit format, so the
Server can enumerate that domain too. This is a dictionary attack, not a break of SHA-256.

`psi/attack_bruteforce.py` performs exactly this attack using only the digests the Server
legitimately received:

```
Phase 1: hash every integer in [0, 10000) and compare.
         10,000 candidates hashed in 0.01s (1,329,227 hashes/second, single-threaded Python)

client1: recovered 4/5 elements
    96dcfae20d4e26466b1f7dac...  ->  1
    ecf2de5604e9c6182e7216c8...  ->  2
    443d7581c97e9580bbf394b5...  ->  5
    99e2d08e26e0cf553853271a...  ->  9
    7171a8e2f17b8501a55f4f94...  ->  NOT FOUND in this range
client2: recovered 3/4 elements
    443d7581c97e9580bbf394b5...  ->  5
    ce21b7c354366862da6409a2...  ->  8
    d78bd3d40637d1b405728f69...  ->  11
    7171a8e2f17b8501a55f4f94...  ->  NOT FOUND in this range

Phase 2: Searching 260400000..260499999 (100,000 candidates).
         52,598 candidates hashed in 0.05s
    7171a8e2f17b8501a55f4f94...  ->  260452597   <-- STUDENT NUMBER RECOVERED

RESULT: 7/7 distinct digests inverted.
```

**Concrete example.** Digest `443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e`
is `SHA-256("CSC8214-PSI-v1|5")`. The Server computed that by trying `x = 5`, and thereby
learned that both clients hold the element `5`, not merely that they share *something*. Every
element of both sets was recovered in well under a second. Even without the prefix assumption of
Phase 2, the whole nine-digit space is 10⁹ candidates, which at the 1.33 million hashes/second
measured here is about 0.2 hours on one unoptimised Python thread. Optimised or parallel
implementations would be faster, but this experiment did not measure them, so the figure that
the evidence supports is the single-thread one, and it is already far too low. The protocol
of A.3 protects the elements from a network eavesdropper but not from the Server.

### One possible improvement, and its limitations

Improvement: blind with a pseudorandom function keyed by a secret the two clients share,
rather than with an unkeyed hash. In Step 0 the clients run a Diffie–Hellman exchange, relayed
by the Server, and derive `k = KDF(g^{ab})` over the 2048-bit MODP group of RFC 3526 [9]. They then send
`HMAC-SHA256(k, T‖x)`, a PRF keyed
by `k` and one of the standard PSI building blocks, instead of `SHA-256(T‖x)`. Equality
still holds for equal elements, so the Server's intersection step is unchanged, but it can no
longer compute the digest of *any* candidate: it saw only `g^a` and `g^b`, and deriving `g^{ab}`
is the computational Diffie–Hellman problem. Run 3 implements this, and the same attack reports:

```
=> the Server cannot compute the digest of ANY candidate value.
=> 0 of the elements can be recovered by hashing candidates.
RESULT: attack fails.
```

**Limitations of the improvement.**

1. **It depends on neither client colluding with the Server.** The key is held by both clients,
   so either can restore the attack simply by handing `k` over, at which point the dictionary
   attack works again on digests the Server has already stored. The improvement defends against
   a curious Server, not against a Server with a confederate.
2. **The Server still learns the metadata.** Set sizes, intersection size and the pattern of
   matches within a session are unchanged, and within a session it can still link repeated
   digests. If the clients reuse `k` across sessions it can link across them too, so `k` must be
   fresh per session.
3. **The key exchange is unauthenticated, and the protocol assumes only a passive Server.** An
   active Server could mount a man-in-the-middle attack on the relay: give each client its own
   key, learn both sets' digests under keys it chose, and brute-force them after all. Defending
   against that needs an authenticated exchange, which adds a key-management burden the plain
   protocol did not have.
4. **Nothing hides the output.** Both clients still learn the intersection, which is inherent to
   PSI; if the intersection is a single element, each learns a fact about the other with
   certainty.

---

# Part B: Blockchain and Smart Contracts

## B.1 Smart contract concept

Lecture 7 [2] defines a contract as something that formalises a relationship and contains a set
of promises made between principals, and attributes the term
**smart contract** to Nick Szabo in 1994: new ways to formalise and secure digital
relationships, using cryptographic and other security mechanisms to stop
algorithmically specifiable relationships being breached and to ensure the agreed terms are
satisfied.

On a blockchain, a smart contract is a program stored and executed on the chain, whose code
captures the logic of the contractual clauses between the parties. The code is run by the
network's nodes: they process and verify the transaction, run the called contract, and reach
consensus on the new state. We can therefore treat a contract as being executed by a trusted
global machine that honestly performs every instruction, even though no individual machine is
trusted.

The effect is to minimise trust, and often operating costs: the parties need not trust one
another, nor an intermediary to hold the money or decide whether to honour the agreement. A
contract is passive: it cannot invoke itself, and acts only when an account calls it. Changing
its state requires a new transaction published to the network.

The same properties are the risks. Deployed code is immutable, so a mistake cannot be patched,
and contracts usually have no private state, which buys transparency at the cost of privacy.

## B.2 Comparison and development environment

The online compiler used in the lab is Remix (`remix.ethereum.org`) [2], a browser-based IDE to
write, compile and debug Solidity contracts, with a built-in test chain (set the Environment
option to the JavaScript VM, which current versions of Remix label the Remix VM) so that
contracts can be deployed and called without spending real ether.

| | Traditional contract | Smart contract |
|---|---|---|
| Expressed in | Natural language | Executable code, e.g. Solidity |
| Interpreted by | Humans; courts resolve ambiguity | The EVM, deterministically |
| Enforcement | After the fact, by a court | At execution time, automatically |
| Intermediaries | Lawyers, banks, escrow agents | None; the chain is the escrow |
| Amendable? | Yes, by agreement of the parties | Not in place, though proxy patterns give an upgrade path |
| Errors | Can be rectified or set aside | Execute as written |
| Cost | Legal fees | Gas, paid per operation |
| State | Private between the parties | Public; contracts usually have no private state |

The deepest difference is that a traditional contract states *intent* and leaves enforcement to
a system that can apply judgement, whereas a smart contract *is* the enforcement and has no
judgement at all. A traditional contract with a typo in a payment clause will usually be
rectified; a smart contract with the same typo pays the wrong amount every time.

A second difference is scope. A smart contract acts only on facts it can see on-chain, so
anything about the physical world must come from a trusted oracle, which reintroduces the
trusted third party the design set out to remove.

## B.3 Security considerations

Take the lab's `Donation` contract [2].

```solidity
pragma solidity ^0.8.20;

contract Donation {
    uint public totalDonated;

    function donate() public payable {
        totalDonated += msg.value;
    }
}
```

`donate()` is `payable`, so it may receive Ether, and `msg.value` is the amount sent in wei;
without `payable` the call would revert. Security questions appear once a withdraw function lets
the money leave.

**Access control.** Any `public` function can be called by anyone, so a withdrawal path must
check its caller. `msg.sender` is set by the EVM and cannot be forged; `tx.origin` must never be
used, as it can be phished through an intermediate contract.

**Reentrancy.** When the contract sends Ether with `call`, the recipient's code runs *before*
the sending function finishes. If it calls back in while the state still says the funds are
unspent, the guard passes twice, which is how The DAO was drained in 2016. The defence is
checks-effects-interactions: validate, write state, call out last. In B.4
`withdrawn = true` executes before the `call`, so a re-entrant call reverts.

**Checking the return value.** `call` reports failure by returning `false`, so an unchecked
result silently loses funds; B.4 checks and reverts.

**Not trusting the raw balance.** `address(this).balance` can be inflated by `selfdestruct`,
bypassing `donate()`, so a campaign testing it could be pushed over its target with no genuine
donation. B.4 tracks its own total.

**Gas and denial of service.** Ethereum's language is Turing-complete, so a contract could, in Lecture 7's
phrase [2], "make the miners work forever", a denial-of-service attack. Gas forces termination: each operation has
an explicit cost, and a transaction costs Gas Limit × Gas Price. Work growing with the number of
contributors can exceed the limit, so each party should withdraw its own share.

**Process.** The lecture's lifecycle [2] ends implementation with: test many times, analyse
security, let others review the code, because deployed code cannot be patched.

## B.4 Crowdfunding contract

Full source, `contracts/Crowdfunding.sol`:

```solidity
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
    error CampaignClosed();
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
    /// @dev Over-funding is accepted, but contributions are refused once the
    ///      funds have been withdrawn: the latch is permanent, so ether sent
    ///      after that point could never be released and would be stranded.
    function contribute() public payable {
        if (msg.value == 0) revert ZeroContribution();
        if (withdrawn) revert CampaignClosed();

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
```

**A design choice worth stating.** The funds always go to `beneficiary` regardless of who calls
`withdraw()`, so restricting the caller is not needed to protect the destination. The caller is
restricted anyway so that the beneficiary controls the *timing* of the payout, rather than
having a stranger trigger the transfer at an arbitrary moment.

### Withdrawal before the target is reached

`withdraw()` checks the caller is the beneficiary, then reaches
`if (totalRaised < target) revert TargetNotReached(totalRaised, target);`. The revert rolls the
whole transaction back atomically: no state changes, no Ether moves, `withdrawn` is untouched,
and the only cost is gas. The error carries both figures, so a wallet can show how much is still
missing. Contributions are therefore safe in the contract until the target is genuinely met.

### Withdrawal after the funds have already been withdrawn

The first successful `withdraw()` sets `withdrawn = true` before sending anything, so a
second call reverts with `AlreadyWithdrawn` and nothing moves. The ordering is what matters:
because the flag is written before the external call, even a beneficiary contract that re-enters
`withdraw()` from its `receive()` function meets the same closed latch, so the funds can leave
exactly once.

Two consequences of that ordering are worth drawing out. First, if the transfer itself fails,
`TransferFailed` reverts the *entire* transaction, including `withdrawn = true`, so a failed
payout does not lock the funds, and the beneficiary can try again. The latch closes only on a
payout that actually succeeded. Second, because the latch is permanent, Ether arriving afterwards
could never be released, so `contribute()` rejects contributions once `withdrawn` is set, with
`CampaignClosed`, rather than letting them be stranded.

### Test results

`npx hardhat run scripts/test_crowdfunding.js` gives 33 passed, 0 failed. Full output:

```text

> csc8214-system-security@1.0.0 test
> hardhat run scripts/test_crowdfunding.js

==========================================================================
B.4  CROWDFUNDING CONTRACT - FUNCTIONAL TESTS
==========================================================================

-- Deployment (REQUIREMENT 2: beneficiary and target recorded) --
  contract    : 0x5FbDB2315678afecb367f032d93F642f64180aa3
  beneficiary : 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
  target      : 10.0 ETH
  PASS  beneficiary stored
  PASS  target stored
  PASS  nothing raised yet
  PASS  not withdrawn yet
  PASS  deploying with a zero beneficiary is rejected  [beneficiary must not be the zero address]
  PASS  deploying with a zero target is rejected  [target must be greater than zero]

-- Contributions (REQUIREMENT 1) --
  alice contributed 4 ETH   -> totalRaised = 4.0 ETH
  bob   contributed 3 ETH   -> totalRaised = 7.0 ETH
  PASS  alice's contribution recorded
  PASS  bob's contribution recorded
  PASS  totalRaised is 7 ETH
  PASS  target not yet reached
  PASS  3 ETH still needed
  PASS  plain transfer handled by receive()
  PASS  totalRaised is 8 ETH
  PASS  a zero-value contribution is rejected  [ZeroContribution]

-- Withdrawal BEFORE the target is reached (REQUIREMENT 3) --
  PASS  beneficiary cannot withdraw below the target  [TargetNotReached]
  PASS  a stranger cannot withdraw either  [NotBeneficiary]
  PASS  funds untouched after failed withdrawals  [8.0 ETH]

-- Crossing the target --
  carol contributed 4 ETH   -> totalRaised = 12.0 ETH
  events emitted            : ContributionReceived, TargetReached
  PASS  TargetReached emitted on the crossing contribution
  PASS  target now reached
  PASS  over-funding accepted (12 ETH > 10 ETH target)
  PASS  TargetReached is not emitted twice

-- Withdrawal AFTER the target is reached --
  PASS  a stranger still cannot withdraw  [NotBeneficiary]
  contract held             : 13.0 ETH
  beneficiary gained        : 13.0 ETH (net of 0.000063697623929552 ETH gas)
  PASS  beneficiary received the full balance
  PASS  contract balance is now zero
  PASS  withdrawn flag is set

-- Withdrawal AFTER the funds have already been withdrawn (REQUIREMENT 4) --
  PASS  the beneficiary cannot withdraw a second time  [AlreadyWithdrawn]
  PASS  a contribution after the withdrawal is refused, not stranded  [CampaignClosed]
  PASS  a plain transfer after the withdrawal is refused too  [CampaignClosed]
  PASS  contract still holds nothing after the refused contributions

-- Reentrancy: a hostile beneficiary calls withdraw() from receive() --
  campaign2 raised          : 5.0 ETH
  PASS  re-entrant call was attempted
  PASS  re-entrant withdrawal FAILED (defence holds)
  PASS  campaign2 paid out exactly once
  PASS  attacker holds only the single legitimate payout  [5.0 ETH]

==========================================================================
RESULT: 33 passed, 0 failed
==========================================================================
```

## B.5 Limitations and improvements

**Limitation 1 (functionality): there is no deadline and no refund.** If the campaign stalls
below its target, `withdraw()` always reverts and there is no other path out of the contract:
every contribution is frozen permanently, and contributors cannot recover money from a campaign
that has plainly failed.

*Improvement:* add a `deadline` set in the constructor and a `refund()` that, after the deadline
and only if the target was missed, lets each contributor withdraw their recorded
`contributions[msg.sender]`, zeroing the stored balance before sending so it cannot be claimed
twice or re-entered.

*Trade-off:* a second money-moving path widens the attack surface, and the refund logic must be
reentrancy-safe in its own right. It also makes the campaign depend on `block.timestamp`, which
validators can nudge, and leaves contributors responsible for claiming; any who never do still
lose their money.

**Limitation 2 (transaction costs).** Every contribution writes two storage slots
(`contributions[msg.sender]` and `totalRaised`) and emits an event, and the caller pays for all
of it: a transaction costs Gas Limit × Gas Price, independently of how much Ether it carries. The
fee therefore falls hardest on small donors, and at busy times can approach the donation itself,
so a contract meant to collect many small amounts works against its own economics.

*Improvement:* accept contributions in batches, so one transaction records many donations and
the fixed cost is shared, and pack the stored fields into smaller `uint` types so fewer storage
slots are written per contribution.

*Trade-off:* batching delays confirmation, and the aggregator must be trusted not to drop
donations, reintroducing the intermediary the design was meant to avoid. Tighter packing makes
the code harder to audit.

---

# Part C: Using Security Tools Correctly

## C.1 Hashing and encryption

No. A hash function must not be used to encrypt sensitive information, because hashing is not
encryption. An encryption scheme uses a key: `Encrypt_k(m) = C`, and the secret key allows the
ciphertext to be decrypted and the original plaintext recovered. A cryptographic hash is a
deterministic, keyless, one-way function that takes an input of arbitrary size and returns a
fixed-size digest, and which is practically infeasible to invert. There is no decryption
function and no key, so information "encrypted" this way cannot be recovered by its legitimate
owner either. Since SHA-256 maps arbitrarily long inputs to 256 bits, information is destroyed
by construction. Confidentiality requires an authenticated cipher such as AES-GCM with a
properly managed key.

A keyed hash does not close the gap. HMAC adds a key and so provides integrity and
authentication, and, as in A.5, stops an observer testing candidate inputs; but it is still
one-way, so it still cannot give the data back.

The second, more dangerous error is assuming a digest *hides* its input. It only does so when
the input is unpredictable. Because the function is public and deterministic, anyone can hash
candidates and compare, so for any low-entropy input (a password, a postcode, a date of birth,
a student number) the protection is defeated by dictionary or exhaustive search. A.5
demonstrates exactly that: every digest sent to the PSI Server, the student number included, was
inverted in under a second.

Hashes have proper uses: integrity checking, digital signatures, and commitments, where
`Com(m, d) = H(m‖d)` hides `m` until the sender opens it and binds the sender to it. For
passwords the right tool is a *slow, salted* function such as Argon2id or bcrypt, whose per-user salt
defeats precomputed tables.

## C.2 Password recovery in Lab 1 (Task 3)

Task 3 [3] demonstrated the misuse `cipher = SHA256(plaintext)`, encryption replaced by a bare
hash. We were given a ciphertext `X` and a list of four candidate passwords, and asked which had
been "encrypted". Hashing each candidate and comparing to `X` recovers the plaintext on the
third attempt (`scripts/lab1_task3_attack.py`):

```text
X = 872715f9eb56b72a64f8f19b6297d54931d26bbc4923ccdd4354059a61dae80b

candidate        SHA-256(candidate)                                              
----------------------------------------------------------------------------------
11211223         1ee56c9d887cf4e7f5d2bb9de1cc712231c7246bff73f7cd971d70b6a88e2c75
Password         e7cf3ef4f17c3999a94f2c6f612e8a888e5b1026878e4e19398b23bd38ec221a
1989-Newcastle   872715f9eb56b72a64f8f19b6297d54931d26bbc4923ccdd4354059a61dae80b  <== MATCH
----------------------------------------------------------------------------------
plaintext Y = '1989-Newcastle', found after 3 of 4 hashes
```

The plaintext was `1989-Newcastle`. Three properties made this possible, and all three had to
hold together.

**No key and no randomness.** The task states that "no secret key or randomness is used to
encrypt the message Y" [3]. Encryption provides confidentiality through a secret key and a random
value; a hash has neither, so an attacker needs nothing before computing the transformation
themselves. `X` was never decrypted; SHA-256 was only run forwards.

**The function is deterministic.** The same plaintext always produces the same digest, so `X`
is a stable fingerprint of its input and equal digests imply equal plaintexts. That is the
leakage the lab warns of: identical plaintext gives identical "ciphertext", so an attacker
detects duplicates and known values.

**The candidate space was tiny.** Four candidates meant at most four hashes, and the match came
on the third. Because SHA-256's 2²⁵⁶ output space is so much larger than four candidates, an
accidental collision is negligible, so the match identifies the password uniquely rather than
merely plausibly.

SHA-256's strength was never the issue; it was used exactly as designed, for a job it was not
designed for. The fixes follow from the three properties: use an authenticated cipher under a
key when the message must be recoverable, and store passwords under a slow, salted KDF such as
Argon2id, whose per-record salt destroys the fingerprint.

---

# Part D: Federated Learning and Privacy-Preserving Data Cleaning

## D.1 Federated learning

**How it supports the two hospitals.** In federated learning the data never moves; the model
does. One round has four steps: the server sends the global model parameters to both hospitals;
each trains that copy locally for several local epochs on its own examples; each returns its
trained parameters, training sample count and scalar metrics, never the examples; and the
server combines the replies with **Federated Averaging (FedAvg)** [4, 5], a sample-count-weighted
average, so a hospital with more examples gets a larger share of the weight. With `nₖ`
the number of training examples at client *k*, `w ← Σₖ (nₖ / Σⱼ nⱼ) wₖ`. If A returns 0.4 after
training on 100 examples and B returns 0.8 on 300, the result is 0.7, not the unweighted 0.6.
Repeating the round gives both a model shaped by the union of their patients.

**Privacy benefit.** Raw patient records stay in the hospital that holds them: there is no
pooled database to breach or subpoena, and each hospital keeps control over access to its own
records while contributing to the shared model.

**Privacy risk that remains.** Keeping examples local does not guarantee privacy: shared
updates still reveal information about the data. Zhu et al. [6] showed training examples can
sometimes be reconstructed from shared gradients *under their experimental conditions*, and
membership inference can reveal whether a person's record was used, which in a hospital
discloses that they were a patient.

The usual mitigations are secure aggregation, which hides individual updates from the server,
and differential privacy, which bounds any one record's influence. With two participants
secure aggregation gives little protection against the other hospital: A knows its own update,
so subtracting it from the aggregate recovers B's exactly. Here differential privacy carries
most of the weight, at a cost in accuracy.

## D.2 Privacy-preserving data cleaning

The method studied is **secure mean imputation using secure aggregation** [7, 8].

**The plaintext baseline.** Writing `mᵢ = 1` when a value is observed, a central server pools
the records and computes `μ = Σᵢ xᵢmᵢ / Σᵢ mᵢ`, which requires receiving every record.

**The secure version.** For the field with gaps, say creatinine, each hospital *k* computes
`sₖ = Σᵢ xₖᵢ mₖᵢ`, the sum of the values it observed, and `nₖ = Σᵢ mₖᵢ`, how many it observed.
Only those protected totals leave the site. Under secure aggregation the coordinator obtains
`S = Σₖ sₖ` and `N = Σₖ nₖ` without seeing either contribution, computes `μ = S / N` and returns
it; each hospital fills its own gaps locally with `μ`. The imputed value is the same
as with pooling, and the coordinator never sees a record.

**Worked example.** Hospital A observes 80, 100 and 120, so `s_A = 300`, `n_A = 3`. Hospital B
observes 90 and 110, so `s_B = 200`, `n_B = 2`. Then `S = 500`, `N = 5`, `μ = 100`.

**How this differs from a central server.** In the plaintext approach the server receives every
record, becomes a new data controller and a single point of failure, and sees the patients
irrelevant to the imputation. Here it sees two totals, and records never leave the hospital.

**Limitations.** The aggregate itself is still revealed, and secure aggregation supports only
counts, sums and means. Medians and regression
imputation need heavier MPC. More sharply, with two hospitals
the aggregate leaks: knowing `μ` and `N`, Hospital A computes `S − s_A = s_B` and
`N − n_A = n_B`, learning B's sum, count and local mean exactly. Secure aggregation protects
against the coordinator here, not against the only other participant.

---

# References

[1] Abadi, A. *Private Set Intersection (PSI)*. CSC8214 System Security, Lecture 3. Newcastle
University.

[2] Abadi, A. *Smart Contracts*. CSC8214 System Security, Lecture 7. Newcastle University.

[3] *CSC8214 Lab 1*, Task 3: Insecure Use of Secure Tool, Using Only Hash Function for
Encryption. Newcastle University.

[4] *Getting Started with Flower: a browser-based introduction to federated learning*. CSC8214
Lab 3. Newcastle University.

[5] McMahan, H.B., Moore, E., Ramage, D., Hampson, S., Arcas, B.A. Communication-Efficient
Learning of Deep Networks from Decentralized Data. AISTATS, 2017. Cited as [1] in Lab 3.

[6] Zhu, L., Liu, Z., Han, S. Deep Leakage from Gradients. NeurIPS, 2019. Cited as [5] in Lab 3.

[7] *Secure Medical Data Cleaning*. CSC8214 System Security lecture. Newcastle University.

[8] Bonawitz, K. et al. Practical Secure Aggregation for Privacy-Preserving Machine Learning.
ACM CCS, 2017.

[9] Kivinen, T., Kojo, M. *More Modular Exponential (MODP) Diffie-Hellman Groups for Internet
Key Exchange (IKE)*. RFC 3526, IETF, 2003.

[10] Bhowmick, A., Boneh, D., Myers, S., Talwar, K., Tarbe, K. *The Apple PSI System*. 2021.
https://www.apple.com/child-safety/pdf/Apple_PSI_System_Security_Protocol_and_Analysis.pdf

[11] *Security Threat Model Review of Apple's Child Safety Features*. Apple, 2021.

[12] Jentsch, D., Ünal, A.B., Mağara, G., Akgün, M. Secure multiparty computation for missing
value imputation. arXiv:2405.18878, 2024. Cited in [7].

---

# Appendix A: Source code

## Listing 1: `psi/common.py`

```python
"""Shared primitives for the CSC8214 private set intersection protocol.

Two blinding modes are supported:

    plain  digest = SHA-256(TAG || element)           the protocol of A.3
    hmac   digest = HMAC-SHA256(k, TAG || element)    the improvement of A.5

In hmac mode the key is agreed between the two clients by Diffie-Hellman, so
the Server cannot compute the digest of a candidate value.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

Element = int | str

# Domain separation. Both clients must use the same tag or no digests match.
TAG = b"CSC8214-PSI-v1|"

# RFC 3526 2048-bit MODP group.
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF",
    16,
)
DH_GENERATOR = 2
DH_PRIVATE_BITS = 256


def encode_element(element: Element) -> bytes:
    """Canonical encoding, so that both clients hash an element identically."""
    if isinstance(element, bool):
        raise TypeError("boolean set elements are not supported")
    if isinstance(element, int):
        return str(element).encode()
    if isinstance(element, str):
        return element.strip().encode()
    raise TypeError(f"unsupported element type: {type(element).__name__}")


def digest(element: Element, key: bytes | None = None) -> str:
    """PROTOCOL STEP 1 - blind one element, keyed if a key is supplied."""
    message = TAG + encode_element(element)
    if key is None:
        return hashlib.sha256(message).hexdigest()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def blind_set(elements: list[Element], key: bytes | None = None) -> dict[str, Element]:
    """Blind a set, returning the client-private table {digest: element}."""
    return {digest(element, key): element for element in elements}


def dh_keypair() -> tuple[int, int]:
    """Return a Diffie-Hellman (private, public) pair."""
    private = secrets.randbits(DH_PRIVATE_BITS)
    return private, pow(DH_GENERATOR, private, DH_PRIME)


def dh_shared_key(private: int, peer_public: int) -> bytes:
    """Derive the 256-bit MAC key from a peer's public value."""
    if not 1 < peer_public < DH_PRIME - 1:
        raise ValueError("invalid peer public key")
    shared = pow(peer_public, private, DH_PRIME)
    raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    return hashlib.sha256(b"CSC8214-PSI-KDF|" + raw).digest()
```

## Listing 2: `psi/server.py`

```python
"""The PSI Server: relays key material, intersects digest lists, logs messages.

The Server holds no input set. It never sees a raw set element; everything it
does receive is kept in a message log exposed at GET /log.

    python3 psi/server.py --port 8214
"""

from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

CLIENTS_PER_SESSION = 2


@dataclass
class Session:
    public_keys: dict[str, int] = field(default_factory=dict)
    digests: dict[str, list[str]] = field(default_factory=dict)
    intersection: list[str] | None = None


class Store:
    """Server state, guarded by a single lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._log: list[dict[str, Any]] = []

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._log.clear()

    def log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._log)

    def record_public_key(self, session_id: str, client_id: str, public_key: int) -> None:
        """PROTOCOL STEP 0 - store a client's Diffie-Hellman public value."""
        with self._lock:
            self._session(session_id).public_keys[client_id] = public_key
            self._append(session_id, "received", client_id, "DH_PUBLIC_KEY",
                         {"public_key_truncated": f"{str(public_key)[:32]}..."})

    def peer_public_key(self, session_id: str, client_id: str) -> tuple[str, int] | None:
        """PROTOCOL STEP 0 - hand a client the other client's public value."""
        with self._lock:
            keys = self._session(session_id).public_keys
            peer = next(((c, k) for c, k in keys.items() if c != client_id), None)
            if peer is not None:
                self._append(session_id, "sent", client_id, "DH_PEER_KEY",
                             {"peer": peer[0],
                              "public_key_truncated": f"{str(peer[1])[:32]}..."})
            return peer

    def record_digests(self, session_id: str, client_id: str, mode: str,
                       digests: list[str]) -> bool:
        """PROTOCOL STEP 2 - store one client's blinded set. Returns True if both are in.

        This log entry is the Server's entire view of the client: no raw set
        element appears in it.
        """
        with self._lock:
            session = self._session(session_id)
            if client_id in session.digests:
                raise KeyError("this client already submitted")
            session.digests[client_id] = digests
            self._append(session_id, "received", client_id, "BLINDED_SET",
                         {"mode": mode, "count": len(digests), "digests": digests})
            return len(session.digests) == CLIENTS_PER_SESSION

    def intersection(self, session_id: str) -> list[str] | None:
        """PROTOCOL STEP 3 - intersect the two digest lists, once both have arrived."""
        with self._lock:
            session = self._session(session_id)
            if len(session.digests) < CLIENTS_PER_SESSION:
                return None
            if session.intersection is None:
                first, second = session.digests.values()
                session.intersection = sorted(set(first) & set(second))
                self._append(session_id, "sent", "both clients", "INTERSECTION",
                             {"count": len(session.intersection),
                              "digests": session.intersection})
            return session.intersection

    def submitted_by(self, session_id: str) -> list[str]:
        with self._lock:
            return sorted(self._session(session_id).digests)

    def _session(self, session_id: str) -> Session:
        return self._sessions.setdefault(session_id, Session())

    def _append(self, session_id: str, direction: str, peer: str, kind: str,
                payload: dict[str, Any]) -> None:
        self._log.append({
            "seq": len(self._log) + 1,
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            "session": session_id,
            "direction": direction,
            "peer": peer,
            "message": kind,
            "payload": payload,
        })


class PSIRequestHandler(BaseHTTPRequestHandler):
    server_version = "CSC8214-PSI-Server/1.0"
    store: Store

    def log_message(self, fmt: str, *args: Any) -> None:
        """Suppress the default stderr access log."""

    def do_GET(self) -> None:
        parts = self._path_parts()

        if parts == ["health"]:
            return self._send(200, {"status": "ok"})

        if parts == ["log"]:
            return self._send(200, {"messages": self.store.log()})

        if len(parts) == 4 and parts[0] == "session" and parts[2] == "peer-key":
            peer = self.store.peer_public_key(parts[1], parts[3])
            if peer is None:
                return self._send(409, {"error": "peer key not posted yet"})
            return self._send(200, {"peer": peer[0], "public_key": str(peer[1])})

        if len(parts) == 3 and parts[0] == "session" and parts[2] == "result":
            intersection = self.store.intersection(parts[1])
            if intersection is None:
                return self._send(409, {"error": "waiting for both clients",
                                        "received_from": self.store.submitted_by(parts[1])})
            return self._send(200, {"intersection": intersection})

        self._send(404, {"error": "unknown endpoint"})

    def do_POST(self) -> None:
        parts = self._path_parts()
        try:
            body = self._body()
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid JSON"})

        if parts == ["reset"]:
            self.store.reset()
            return self._send(200, {"status": "reset"})

        if len(parts) == 3 and parts[0] == "session" and parts[2] == "key":
            client_id, public_key = body.get("client_id"), body.get("public_key")
            if not client_id or public_key is None:
                return self._send(400, {"error": "client_id and public_key required"})
            self.store.record_public_key(parts[1], client_id, int(public_key))
            return self._send(200, {"status": "stored"})

        if len(parts) == 3 and parts[0] == "session" and parts[2] == "digests":
            client_id, digests = body.get("client_id"), body.get("digests")
            if not client_id or not isinstance(digests, list):
                return self._send(400, {"error": "client_id and digests required"})
            try:
                ready = self.store.record_digests(
                    parts[1], client_id, body.get("mode", "unspecified"),
                    [str(d) for d in digests])
            except KeyError as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"status": "stored", "both_clients_ready": ready})

        self._send(404, {"error": "unknown endpoint"})

    def _path_parts(self) -> list[str]:
        return [p for p in urlparse(self.path).path.split("/") if p]

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def _send(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve(host: str, port: int) -> None:
    handler = type("BoundHandler", (PSIRequestHandler,), {"store": Store()})
    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"[server] listening on http://{host}:{port} (no input set of its own)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] shutting down", flush=True)
    finally:
        httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 PSI Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8214)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
```

## Listing 3: `psi/client.py`

```python
"""The PSI Client. Run once as client1 and once as client2.

    python3 psi/client.py --client-id client1 --set 1,2,5,9,260452597

Protocol steps, numbered as in Question A.3 of the report:

    STEP 0  agree a MAC key with the other client (keyed variant only)
    STEP 1  blind the local set, keeping a private {digest: element} table
    STEP 2  send the shuffled digests to the Server
    STEP 3  the Server intersects the two digest lists
    STEP 4  invert the returned digests through the local table
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.request
from typing import Any

from common import Element, blind_set, dh_keypair, dh_shared_key

DEFAULT_SERVER = "http://127.0.0.1:8214"
POLL_ATTEMPTS = 100
POLL_DELAY_SECONDS = 0.1


def _post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _poll(url: str, label: str) -> dict[str, Any]:
    """Wait for an endpoint that only answers once the peer has acted."""
    for _ in range(POLL_ATTEMPTS):
        status, body = _get(url)
        if status == 200:
            return body
        time.sleep(POLL_DELAY_SECONDS)
    raise TimeoutError(f"timed out waiting for {label}")


def parse_set(raw: str) -> list[Element]:
    """Parse "1,2,5,9,ID" into a list, keeping numeric elements as integers."""
    elements: list[Element] = []
    for token in (t.strip() for t in raw.split(",")):
        if token:
            elements.append(int(token) if token.lstrip("-").isdigit() else token)
    return elements


def run_client(client_id: str, elements: list[Element], mode: str, session: str,
               server: str = DEFAULT_SERVER, verbose: bool = True) -> dict[str, Any]:
    def say(message: str) -> None:
        if verbose:
            print(f"[{client_id}] {message}", flush=True)

    say(f"private set = {sorted(map(str, elements))}  (never leaves this process)")

    # PROTOCOL STEP 0: Diffie-Hellman with the other client, relayed by the Server.
    # Used only by the improved (keyed) variant of A.5; the protocol of A.3
    # starts at Step 1.
    key: bytes | None = None
    if mode == "hmac":
        private, public = dh_keypair()
        _post(f"{server}/session/{session}/key",
              {"client_id": client_id, "public_key": str(public)})
        say("sent my Diffie-Hellman public value to the Server for relay")
        peer = _poll(f"{server}/session/{session}/peer-key/{client_id}", "peer DH key")
        key = dh_shared_key(private, int(peer["public_key"]))
        say(f"derived shared MAC key with {peer['peer']} "
            f"(first 8 bytes: {key[:8].hex()}) - the Server cannot derive this")

    # PROTOCOL STEP 1: blind locally. The table is what inverts the Server's answer.
    table = blind_set(elements, key)
    say(f"blinded {len(table)} elements with "
        f"{'HMAC-SHA256 (keyed)' if key else 'SHA-256 (unkeyed)'}")
    for element_digest, element in table.items():
        say(f"    {element!s:>12}  ->  {element_digest}")

    # PROTOCOL STEP 2: send shuffled, so position cannot leak the ordering of the set.
    outgoing = list(table)
    random.shuffle(outgoing)
    _post(f"{server}/session/{session}/digests",
          {"client_id": client_id, "mode": mode, "digests": outgoing})
    say(f"sent {len(outgoing)} shuffled digests to the Server (no raw elements sent)")

    # PROTOCOL STEP 3 happens on the Server.
    # PROTOCOL STEP 4: only this client holds the table, so only it can invert the result.
    returned = _poll(f"{server}/session/{session}/result", "intersection")["intersection"]
    say(f"Server returned {len(returned)} intersecting digest(s)")
    intersection = sorted((table[d] for d in returned if d in table),
                          key=lambda value: (isinstance(value, str), value))
    say(f"INTERSECTION = {intersection}")

    return {
        "client_id": client_id,
        "mode": mode,
        "input_set": list(elements),
        "digests_sent": outgoing,
        "lookup_table": {d: str(e) for d, e in table.items()},
        "intersection_digests": returned,
        "intersection": intersection,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 PSI Client")
    parser.add_argument("--client-id", required=True, choices=["client1", "client2"])
    parser.add_argument("--set", required=True, help="comma-separated set elements")
    parser.add_argument("--mode", default="plain", choices=["plain", "hmac"])
    parser.add_argument("--session", default="run1")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    args = parser.parse_args()

    run_client(args.client_id, parse_set(args.set), args.mode, args.session, args.server)


if __name__ == "__main__":
    main()
```

## Listing 4: `scripts/test_crowdfunding.js`

```javascript
/**
 * Question B.4: functional tests for Crowdfunding.sol on Hardhat's EVM.
 *
 *   npx hardhat run scripts/test_crowdfunding.js
 */

const { ethers } = require("hardhat");

const ONE_ETH_HEX = "0xDE0B6B3A7640000";

let passed = 0;
let failed = 0;

function check(description, condition, detail = "") {
  const suffix = detail ? `  [${detail}]` : "";
  console.log(`  ${condition ? "PASS" : "FAIL"}  ${description}${suffix}`);
  condition ? (passed += 1) : (failed += 1);
}

async function expectRevert(description, promise, expectedError) {
  try {
    await promise;
    check(description, false, "transaction unexpectedly succeeded");
  } catch (error) {
    check(description, (error.message || String(error)).includes(expectedError), expectedError);
  }
}

const eth = (value) => ethers.parseEther(String(value));
const fmt = (wei) => `${ethers.formatEther(wei)} ETH`;

function eventNames(receipt, contract) {
  return receipt.logs
    .map((log) => {
      try {
        return contract.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .map((event) => event.name);
}

async function deployCampaign(beneficiaryAddress, targetAmount) {
  const campaign = await ethers.deployContract("Crowdfunding", [beneficiaryAddress, targetAmount]);
  await campaign.waitForDeployment();
  return campaign;
}

async function testDeployment(beneficiary, target) {
  console.log("\n-- Deployment (REQUIREMENT 2: beneficiary and target recorded) --");
  const campaign = await deployCampaign(beneficiary.address, target);

  console.log(`  contract    : ${await campaign.getAddress()}`);
  console.log(`  beneficiary : ${beneficiary.address}`);
  console.log(`  target      : ${fmt(target)}`);

  check("beneficiary stored", (await campaign.beneficiary()) === beneficiary.address);
  // ethers v6 uses contract.target for the contract's own address, so the
  // Solidity getter of the same name is reached through getFunction().
  check("target stored", (await campaign.getFunction("target")()) === target);
  check("nothing raised yet", (await campaign.totalRaised()) === 0n);
  check("not withdrawn yet", (await campaign.withdrawn()) === false);

  await expectRevert(
    "deploying with a zero beneficiary is rejected",
    deployCampaign(ethers.ZeroAddress, target),
    "beneficiary must not be the zero address"
  );
  await expectRevert(
    "deploying with a zero target is rejected",
    deployCampaign(beneficiary.address, 0),
    "target must be greater than zero"
  );

  return campaign;
}

async function testContributions(campaign, { alice, bob, carol }) {
  console.log("\n-- Contributions (REQUIREMENT 1) --");
  const address = await campaign.getAddress();

  await (await campaign.connect(alice).contribute({ value: eth(4) })).wait();
  console.log(`  alice contributed 4 ETH   -> totalRaised = ${fmt(await campaign.totalRaised())}`);
  await (await campaign.connect(bob).contribute({ value: eth(3) })).wait();
  console.log(`  bob   contributed 3 ETH   -> totalRaised = ${fmt(await campaign.totalRaised())}`);

  check("alice's contribution recorded", (await campaign.contributions(alice.address)) === eth(4));
  check("bob's contribution recorded", (await campaign.contributions(bob.address)) === eth(3));
  check("totalRaised is 7 ETH", (await campaign.totalRaised()) === eth(7));
  check("target not yet reached", (await campaign.targetReached()) === false);
  check("3 ETH still needed", (await campaign.remaining()) === eth(3));

  await (await carol.sendTransaction({ to: address, value: eth(1) })).wait();
  check("plain transfer handled by receive()", (await campaign.contributions(carol.address)) === eth(1));
  check("totalRaised is 8 ETH", (await campaign.totalRaised()) === eth(8));

  await expectRevert(
    "a zero-value contribution is rejected",
    campaign.connect(alice).contribute({ value: 0 }),
    "ZeroContribution"
  );
}

async function testWithdrawBeforeTarget(campaign, { beneficiary, mallory }) {
  console.log("\n-- Withdrawal BEFORE the target is reached (REQUIREMENT 3) --");
  await expectRevert(
    "beneficiary cannot withdraw below the target",
    campaign.connect(beneficiary).withdraw(),
    "TargetNotReached"
  );
  await expectRevert(
    "a stranger cannot withdraw either",
    campaign.connect(mallory).withdraw(),
    "NotBeneficiary"
  );
  check(
    "funds untouched after failed withdrawals",
    (await ethers.provider.getBalance(await campaign.getAddress())) === eth(8),
    fmt(eth(8))
  );
}

async function testCrossingTarget(campaign, { alice, carol }) {
  console.log("\n-- Crossing the target --");
  const receipt = await (await campaign.connect(carol).contribute({ value: eth(4) })).wait();
  const events = eventNames(receipt, campaign);

  console.log(`  carol contributed 4 ETH   -> totalRaised = ${fmt(await campaign.totalRaised())}`);
  console.log(`  events emitted            : ${events.join(", ")}`);
  check("TargetReached emitted on the crossing contribution", events.includes("TargetReached"));
  check("target now reached", (await campaign.targetReached()) === true);
  check("over-funding accepted (12 ETH > 10 ETH target)", (await campaign.totalRaised()) === eth(12));

  const later = await (await campaign.connect(alice).contribute({ value: eth(1) })).wait();
  check("TargetReached is not emitted twice", !eventNames(later, campaign).includes("TargetReached"));
}

async function testWithdrawAfterTarget(campaign, { beneficiary, mallory }) {
  console.log("\n-- Withdrawal AFTER the target is reached --");
  const address = await campaign.getAddress();

  await expectRevert(
    "a stranger still cannot withdraw",
    campaign.connect(mallory).withdraw(),
    "NotBeneficiary"
  );

  const before = await ethers.provider.getBalance(beneficiary.address);
  const held = await ethers.provider.getBalance(address);
  const receipt = await (await campaign.connect(beneficiary).withdraw()).wait();
  const gas = receipt.gasUsed * receipt.gasPrice;
  const after = await ethers.provider.getBalance(beneficiary.address);

  console.log(`  contract held             : ${fmt(held)}`);
  console.log(`  beneficiary gained        : ${fmt(after - before + gas)} (net of ${fmt(gas)} gas)`);
  check("beneficiary received the full balance", after - before + gas === held);
  check("contract balance is now zero", (await ethers.provider.getBalance(address)) === 0n);
  check("withdrawn flag is set", (await campaign.withdrawn()) === true);
}

async function testDoubleWithdraw(campaign, { beneficiary, bob }) {
  console.log("\n-- Withdrawal AFTER the funds have already been withdrawn (REQUIREMENT 4) --");
  await expectRevert(
    "the beneficiary cannot withdraw a second time",
    campaign.connect(beneficiary).withdraw(),
    "AlreadyWithdrawn"
  );

  await expectRevert(
    "a contribution after the withdrawal is refused, not stranded",
    campaign.connect(bob).contribute({ value: eth(2) }),
    "CampaignClosed"
  );
  await expectRevert(
    "a plain transfer after the withdrawal is refused too",
    bob.sendTransaction({ to: await campaign.getAddress(), value: eth(2) }),
    "CampaignClosed"
  );
  check(
    "contract still holds nothing after the refused contributions",
    (await ethers.provider.getBalance(await campaign.getAddress())) === 0n
  );
}

async function testReentrancy({ alice }) {
  console.log("\n-- Reentrancy: a hostile beneficiary calls withdraw() from receive() --");
  const attacker = await ethers.deployContract("ReentrantBeneficiary");
  await attacker.waitForDeployment();
  const attackerAddress = await attacker.getAddress();

  const campaign = await deployCampaign(attackerAddress, eth(5));
  const campaignAddress = await campaign.getAddress();
  await (await attacker.setCampaign(campaignAddress)).wait();
  await (await campaign.connect(alice).contribute({ value: eth(5) })).wait();
  console.log(`  campaign2 raised          : ${fmt(await campaign.totalRaised())}`);

  // withdraw() is onlyBeneficiary, so the call must come from the attacker.
  // Its balance is set directly: a normal transfer would run its receive().
  const attackerSigner = await ethers.getImpersonatedSigner(attackerAddress);
  await ethers.provider.send("hardhat_setBalance", [attackerAddress, ONE_ETH_HEX]);
  await (await campaign.connect(attackerSigner).withdraw()).wait();

  check("re-entrant call was attempted", (await attacker.reentryAttempts()) === 1n);
  check("re-entrant withdrawal FAILED (defence holds)", (await attacker.reentrySucceeded()) === false);
  check("campaign2 paid out exactly once", (await ethers.provider.getBalance(campaignAddress)) === 0n);
  check(
    "attacker holds only the single legitimate payout",
    (await attacker.amountReceived()) === eth(5),
    fmt(await attacker.amountReceived())
  );
}

async function main() {
  const [, beneficiary, alice, bob, carol, mallory] = await ethers.getSigners();
  const accounts = { beneficiary, alice, bob, carol, mallory };
  const target = eth(10);

  console.log("=".repeat(74));
  console.log("B.4  CROWDFUNDING CONTRACT - FUNCTIONAL TESTS");
  console.log("=".repeat(74));

  const campaign = await testDeployment(beneficiary, target);
  await testContributions(campaign, accounts);
  await testWithdrawBeforeTarget(campaign, accounts);
  await testCrossingTarget(campaign, accounts);
  await testWithdrawAfterTarget(campaign, accounts);
  await testDoubleWithdraw(campaign, accounts);
  await testReentrancy(accounts);

  console.log(`\n${"=".repeat(74)}`);
  console.log(`RESULT: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(74));
  if (failed > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

## Listing 5: `psi/attack_bruteforce.py`

```python
"""Question A.5: the Server tries to invert the digests it legitimately received.

Against the unkeyed protocol of A.3 this succeeds, because the hash function is
public and deterministic and the element domain is tiny. Against the keyed
variant it fails, because the Server holds no key.

    python3 psi/attack_bruteforce.py --session run1 --id-prefix 2604
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from collections.abc import Iterable
from typing import Any

from common import Element, digest

DEFAULT_SERVER = "http://127.0.0.1:8214"
SMALL_INTEGER_RANGE = 10_000
STUDENT_NUMBER_DIGITS = 9


def fetch_log(server: str) -> list[dict[str, Any]]:
    with urllib.request.urlopen(f"{server}/log", timeout=10) as response:
        return json.loads(response.read())["messages"]


def harvest(log: list[dict[str, Any]], session: str) -> tuple[dict[str, list[str]], str]:
    """Everything the Server holds for one session, and the mode used."""
    digests: dict[str, list[str]] = {}
    mode = "unknown"
    for message in log:
        if message["session"] == session and message["message"] == "BLINDED_SET":
            digests[message["peer"]] = message["payload"]["digests"]
            mode = message["payload"].get("mode", "unknown")
    return digests, mode


def brute_force(targets: set[str], candidates: Iterable[Element]
                ) -> tuple[dict[str, Element], int]:
    """Hash candidates until every target digest is matched."""
    recovered: dict[str, Element] = {}
    tried = 0
    for candidate in candidates:
        tried += 1
        found = digest(candidate)
        if found in targets:
            recovered[found] = candidate
            if len(recovered) == len(targets):
                break
    return recovered, tried


def report_keyed_failure() -> None:
    print("  The digests are HMAC-SHA256 under a key agreed between the two")
    print("  clients by Diffie-Hellman. The Server relayed the public values")
    print("  g^a and g^b but cannot compute g^ab, so it has no key.")
    print("  => the Server cannot compute the digest of ANY candidate value.")
    print("  => 0 of the elements can be recovered by hashing candidates.")
    print()
    print("  RESULT: attack fails.")


def main() -> None:
    parser = argparse.ArgumentParser(description="A.5 brute-force attack by the Server")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--session", default="run1")
    parser.add_argument("--small-range", type=int, default=SMALL_INTEGER_RANGE)
    parser.add_argument("--id-prefix", default=None,
                        help="student-number prefix the Server is assumed to know")
    parser.add_argument("--id-width", type=int, default=5,
                        help="number of unknown digits after the prefix")
    args = parser.parse_args()

    harvested, mode = harvest(fetch_log(args.server), args.session)
    if not harvested:
        raise SystemExit(f"no BLINDED_SET messages logged for session {args.session!r}")

    print("=" * 74)
    print(f"A.5  SERVER-SIDE BRUTE-FORCE ATTACK ON SESSION {args.session!r}")
    print("=" * 74)
    for client, digests in sorted(harvested.items()):
        print(f"  Server holds {len(digests)} digests from {client}")
    print(f"  Blinding mode used by the clients: {mode}")
    print()

    if mode == "hmac":
        return report_keyed_failure()

    targets = {d for digests in harvested.values() for d in digests}

    print(f"  Phase 1: hash every integer in [0, {args.small_range}) and compare.")
    started = time.perf_counter()
    recovered, tried = brute_force(targets, range(args.small_range))
    elapsed = time.perf_counter() - started
    rate = tried / max(elapsed, 1e-9)
    print(f"           {tried:,} candidates hashed in {elapsed:.2f}s "
          f"({rate:,.0f} hashes/second, single-threaded Python)")
    print()

    for client, digests in sorted(harvested.items()):
        found = {d: recovered[d] for d in digests if d in recovered}
        print(f"  {client}: recovered {len(found)}/{len(digests)} elements")
        for element_digest, value in sorted(
                found.items(), key=lambda item: (isinstance(item[1], str), item[1])):
            print(f"      {element_digest[:24]}...  ->  {value}")
        for element_digest in (d for d in digests if d not in recovered):
            print(f"      {element_digest[:24]}...  ->  NOT FOUND in this range")
    print()

    remaining = targets - set(recovered)
    if remaining:
        print(f"  Phase 2: {len(remaining)} digest(s) survived phase 1. These are")
        print("           consistent with a student number. A student number is")
        print("           NOT secret and follows a published format, so the")
        print("           Server can search that domain too.")
        if args.id_prefix is not None:
            space = 10 ** args.id_width
            prefix, width = args.id_prefix, args.id_width
            print(f"           Searching {prefix}{'0' * width}..{prefix}{'9' * width} "
                  f"({space:,} candidates).")
            # Candidates are generated as strings so that a student number with
            # a letter prefix is covered as easily as a purely numeric one.
            started = time.perf_counter()
            found, tried = brute_force(
                remaining, (f"{prefix}{i:0{width}d}" for i in range(space)))
            elapsed = time.perf_counter() - started
            print(f"           {tried:,} candidates hashed in {elapsed:.2f}s")
            for element_digest, value in found.items():
                print(f"      {element_digest[:24]}...  ->  {value}"
                      "   <-- STUDENT NUMBER RECOVERED")
            recovered.update(found)
            remaining = targets - set(recovered)
        full_space = 10 ** STUDENT_NUMBER_DIGITS
        print("           Even with no hint at all, the whole 9-digit space is")
        print(f"           {full_space:,} candidates: about "
              f"{full_space / rate / 3600:.1f} hours in this unoptimised Python,")
        print("           and seconds on a GPU. The domain, not the hash, is the")
        print("           weakness.")
    print()
    print(f"  RESULT: {len(recovered)}/{len(targets)} distinct digests inverted.")
    if remaining:
        print(f"          {len(remaining)} digest(s) still unknown "
              "(outside the ranges searched here).")


if __name__ == "__main__":
    main()
```

## Listing 6: `psi/run_experiments.py`

```python
"""Question A.4: runs the whole of Part A and writes the outputs to results/.

    RUN 1   the sets given in the question
    RUN 2   Client 2's set modified so the intersection changes
    RUN 3   the sets of Run 1 with the keyed blinding of A.5
    ATTACK  the Server brute-forcing the Run 1 and Run 3 digests

Starts the Server itself unless one is already listening.

    python3 psi/run_experiments.py --student-id 260452597
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from client import Element, run_client

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
DEFAULT_PORT = 8214
STARTUP_ATTEMPTS = 50
STARTUP_DELAY_SECONDS = 0.1


class Tee:
    """Mirror stdout into a transcript file."""

    def __init__(self, stream: Any, path: Path) -> None:
        self.stream = stream
        self.file = path.open("w", encoding="utf-8")

    def write(self, data: str) -> int:
        self.stream.write(data)
        self.file.write(data)
        return len(data)

    def flush(self) -> None:
        self.stream.flush()
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def server_is_up(server: str) -> bool:
    try:
        with urllib.request.urlopen(f"{server}/health", timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def start_server(server: str, port: int) -> subprocess.Popen[str] | None:
    if server_is_up(server):
        print(f"[runner] a Server is already listening on {server}")
        return None
    print(f"[runner] starting the Server on port {port} ...")
    process = subprocess.Popen(
        [sys.executable, str(HERE / "server.py"), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(STARTUP_ATTEMPTS):
        if server_is_up(server):
            print(f"[runner] Server is up on {server}")
            return process
        time.sleep(STARTUP_DELAY_SECONDS)
    process.terminate()
    raise SystemExit("the Server failed to start")


def post(server: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{server}{path}", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def get(server: str, path: str) -> dict[str, Any]:
    with urllib.request.urlopen(f"{server}{path}", timeout=10) as response:
        return json.loads(response.read())


def banner(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def run_session(server: str, session: str, mode: str,
                set1: list[Element], set2: list[Element]) -> dict[str, Any]:
    """Run both clients concurrently, as two independent parties."""
    results: dict[str, Any] = {}
    errors: list[BaseException] = []

    def worker(client_id: str, elements: list[Element]) -> None:
        try:
            results[client_id] = run_client(client_id, elements, mode, session, server)
        except BaseException as exc:  # re-raised in the main thread below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=args)
               for args in (("client1", set1), ("client2", set2))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise errors[0]
    return results


def print_server_view(server: str, session: str) -> list[dict[str, Any]]:
    """Print exactly what the Server received and sent for one session."""
    log = [m for m in get(server, "/log")["messages"] if m["session"] == session]
    print(f"\n--- MESSAGES AT THE SERVER for session {session!r} "
          "(this is the Server's ENTIRE view) ---")
    for message in log:
        arrow = "<--" if message["direction"] == "received" else "-->"
        print(f"  [{message['seq']:>2}] {message['time']}  "
              f"Server {arrow} {message['peer']:<12} {message['message']}")
        payload = message["payload"]
        if message["message"] == "BLINDED_SET":
            print(f"        mode={payload['mode']}  count={payload['count']}")
        elif message["message"] == "INTERSECTION":
            print(f"        count={payload['count']}")
        else:
            print(f"        {payload}")
            continue
        for element_digest in payload["digests"]:
            print(f"          {element_digest}")
    print("  NOTE: no raw set element appears anywhere above.")
    return log


def parse_student_id(raw: str) -> Element:
    """Keep the ID numeric when it is, but tolerate a letter prefix."""
    value = raw.strip()
    return int(value) if value.lstrip("-").isdigit() else value


def main() -> None:
    parser = argparse.ArgumentParser(description="CSC8214 Part A experiment runner")
    parser.add_argument("--student-id",
                        default=os.environ.get("CSC8214_STUDENT_ID", "260452597"))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--server", default=None)
    args = parser.parse_args()

    server = args.server or f"http://127.0.0.1:{args.port}"
    student_id = parse_student_id(args.student_id)

    RESULTS.mkdir(exist_ok=True)
    tee = Tee(sys.stdout, RESULTS / "transcript.txt")
    sys.stdout = tee

    process = None
    try:
        process = start_server(server, args.port)
        post(server, "/reset", {})

        set1: list[Element] = [1, 2, 5, 9, student_id]
        set2: list[Element] = [5, 8, 11, student_id]
        # A.4(ii): 5 removed and 2 added, so the intersection must change.
        set2_modified: list[Element] = [2, 8, 11, student_id]

        runs = [
            ("run1", "plain", set1, set2,
             "RUN 1 (A.4 i) - the sets given in the question, plain SHA-256",
             [f"  Client 1 set: {{1, 2, 5, 9, ID}}  with ID = {student_id}",
              f"  Client 2 set: {{5, 8, 11, ID}}    with ID = {student_id}",
              f"  Expected intersection: {{5, {student_id}}}"]),
            ("run2", "plain", set1, set2_modified,
             "RUN 2 (A.4 ii) - Client 2's set modified, plain SHA-256",
             ["  Client 1 set: {1, 2, 5, 9, ID}  (unchanged)",
              "  Client 2 set: {2, 8, 11, ID}    (5 removed, 2 added)",
              f"  Expected intersection: {{2, {student_id}}}"]),
            ("run3", "hmac", set1, set2,
             "RUN 3 (A.5 improvement) - same sets as Run 1, keyed HMAC-SHA256",
             ["  The two clients first agree a key by Diffie-Hellman, relayed by",
              "  the Server. The Server sees g^a and g^b but cannot derive g^ab."]),
        ]

        all_results: dict[str, Any] = {}
        for session, mode, first, second, title, preamble in runs:
            banner(title)
            print("\n".join(preamble))
            print()
            clients = run_session(server, session, mode, first, second)
            key = "run3_hmac" if session == "run3" else session
            all_results[key] = {"clients": clients,
                                "server_log": print_server_view(server, session)}

        # The Server is assumed to know all but the last five characters of a
        # student number, which is not a secret in the first place.
        id_prefix = str(student_id)[:-5]
        for session in ("run1", "run3"):
            print()
            attack = subprocess.run(
                [sys.executable, str(HERE / "attack_bruteforce.py"),
                 "--server", server, "--session", session,
                 "--id-prefix", id_prefix, "--id-width", "5"],
                capture_output=True, text=True, cwd=str(HERE), check=False)
            print(attack.stdout, end="")
            if attack.stderr:
                print(attack.stderr, end="", file=sys.stderr)

        banner("SUMMARY")
        for name, payload in all_results.items():
            first = payload["clients"]["client1"]["intersection"]
            second = payload["clients"]["client2"]["intersection"]
            print(f"  {name:<10} client1 output = {first}")
            print(f"  {'':<10} client2 output = {second}")
            print(f"  {'':<10} both clients agree: {first == second}")

        (RESULTS / "results.json").write_text(
            json.dumps(all_results, indent=2, default=str), encoding="utf-8")
        (RESULTS / "server_log_full.json").write_text(
            json.dumps(get(server, "/log"), indent=2), encoding="utf-8")
        print()
        for name in ("results.json", "server_log_full.json", "transcript.txt"):
            print(f"  Written: results/{name}")
    finally:
        sys.stdout = tee.stream
        tee.close()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            print("[runner] Server stopped")


if __name__ == "__main__":
    main()
```

## Listing 7: `contracts/ReentrantBeneficiary.sol`

```solidity
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
```

## Listing 8: `scripts/lab1_task3_attack.py`

```python
"""Question C.2: the dictionary attack from Lab 1, Task 3.

Task 3 replaces encryption with a bare hash, cipher = SHA256(plaintext), and
supplies a ciphertext X together with a list of candidate passwords. Because
the transformation is unkeyed, deterministic and the candidate list is tiny,
the plaintext is recovered by hashing each candidate and comparing.

    python3 scripts/lab1_task3_attack.py
"""

from __future__ import annotations

import hashlib

X = "872715f9eb56b72a64f8f19b6297d54931d26bbc4923ccdd4354059a61dae80b"
CANDIDATES = ["11211223", "Password", "1989-Newcastle", "02.10.1999"]


def sha256_hex(text: str) -> str:
    """The lab's own construction: SHA-256 over the UTF-8 bytes, as hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> None:
    print(f"X = {X}\n")
    print(f"{'candidate':<16} {'SHA-256(candidate)':<64}")
    print("-" * 82)

    recovered, tried = None, 0
    for candidate in CANDIDATES:
        tried += 1
        digest = sha256_hex(candidate)
        marker = "  <== MATCH" if digest == X else ""
        print(f"{candidate:<16} {digest:<64}{marker}")
        if digest == X:
            recovered = candidate
            break

    print("-" * 82)
    if recovered is None:
        print("no candidate matched X")
    else:
        print(f"plaintext Y = {recovered!r}, found after {tried} of "
              f"{len(CANDIDATES)} hashes")


if __name__ == "__main__":
    main()
```
