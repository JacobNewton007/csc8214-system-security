# CSC8214 System Security — Assignment and Report

**Student number (ID):** `240000000`  ← *replace with your own student number and re-run
`python3 psi/run_experiments.py --student-id <your number>`; every digest below that involves
ID will change, and the report text tells you which ones those are.*

**Submitted files**

| File | What it is |
|---|---|
| `psi/common.py` | hashing, canonical encoding, Diffie–Hellman helpers |
| `psi/server.py` | the Server (HTTP, no input set of its own) |
| `psi/client.py` | the Client (run twice: `client1`, `client2`) |
| `psi/run_experiments.py` | starts the Server and runs Runs 1–3 and the attacks |
| `psi/attack_bruteforce.py` | the Server attacking the digests it received (A.5) |
| `contracts/Crowdfunding.sol` | the crowdfunding contract (B.4) |
| `contracts/ReentrantBeneficiary.sol` | hostile beneficiary used in testing |
| `scripts/test_crowdfunding.js` | 32 functional tests for the contract |
| `results/transcript.txt` | full output of Runs 1–3 and the attacks |
| `results/crowdfunding_tests.txt` | full output of the contract tests |

---

# Part A — Private Set Intersection (15 marks)

## A.1 Concept (3 marks)

Private Set Intersection (PSI) is a secure two- or multi-party computation protocol in which
each party holds a private set and the parties jointly compute the intersection of those sets.
The security requirement is that the parties learn the intersection **and nothing else**: no
party should learn any element the other party holds outside the common part, nor anything
about the rest of the other party's set beyond what the intersection itself implies.

PSI solves a problem that an obvious "just send me your list" approach cannot. Comparing two
lists normally requires one side to disclose its whole list, which is exactly the disclosure
that data-protection law, commercial confidentiality, or simple mistrust forbids. PSI replaces
that disclosure with a cryptographic protocol whose output is restricted to the overlap.

Several constructions exist. *Naive hashing* has each party hash its elements and compare
digests; it is simple and fast but only secure when the element domain has high entropy,
because a hash function is public and deterministic, so anyone can hash candidate values and
compare. *Diffie–Hellman based PSI* makes each party exponentiate the other's hashed elements
with its own secret exponent, so the compared values are blinded by a secret the opponent does
not hold. *Oblivious-transfer-based PSI* is the fastest modern approach, and
*homomorphic-encryption* based PSI minimises communication. Variants include PSI-cardinality
(the parties learn only the size of the intersection) and PSI-sum (an aggregate over the
intersection).

Security is stated against a threat model. The *semi-honest* (honest-but-curious) model assumes
parties follow the protocol but try to infer what they can from the transcript; the *malicious*
model allows arbitrary deviation, including sending fabricated inputs, and requires stronger
and more expensive protocols.

*(≈290 words)*

## A.2 Application (3 marks)

A real-world application is **private contact discovery in an encrypted messaging service**,
as used by Signal. When a user installs the app, the app needs to work out which of the
contacts in the user's phone already use the service, so that it can show them as reachable.
The naive implementation uploads the user's entire address book to the provider's servers.

That naive version is a serious privacy failure. The address book is not only the user's
personal data: it is personal data about hundreds of third parties who never installed the app
and never consented to anything. It reveals the user's complete social graph, including
relationships the user may have strong reasons to keep private — a journalist's sources, a
patient's doctor, a person's contacts at a support service. A breach of, or a legal demand on,
the provider exposes all of it at once, and under the UK GDPR the provider is processing
special-category-adjacent data it has no need to hold.

PSI fits this setting precisely because the computation genuinely needed is an intersection:
the user's contacts ∩ the service's registered users. With PSI the user learns which of their
own contacts are registered, which is the entire point of the feature, while the server learns
neither the user's address book nor which of its registered users were matched. The feature is
delivered and the data minimisation principle is satisfied at the same time.

A second, commercially important example is **private ad-conversion measurement** (Google's
Private Join and Compute): an advertiser and a retailer compute how many people who saw an
advert later made a purchase, without either side handing over its customer list.

*(≈280 words)*

## A.3 Protocol design (3 marks)

**Parties and inputs.** Client 1 holds `X₁ = {1, 2, 5, 9, ID}`; Client 2 holds
`X₂ = {5, 8, 11, ID}`, where `ID` is my student number. The Server has no input set. The
security goal is that both clients learn `X₁ ∩ X₂` while the Server receives no raw element.

**Primitive.** A cryptographic hash function `H = SHA-256`, used with a fixed
domain-separation tag `T = "CSC8214-PSI-v1|"` and a fixed canonical encoding of elements
(decimal ASCII for integers). Both clients must use the identical tag and encoding, otherwise
equal elements would hash differently and the intersection would come out empty.

**Messages exchanged.**

| # | From → To | Message | Contents |
|---|---|---|---|
| 1 | C1 → S | `BLINDED_SET` | `D₁ = shuffle({ H(T‖x) : x ∈ X₁ })` |
| 2 | C2 → S | `BLINDED_SET` | `D₂ = shuffle({ H(T‖x) : x ∈ X₂ })` |
| 3 | S → C1, C2 | `INTERSECTION` | `I = D₁ ∩ D₂` (a set of digests) |

**Steps.**

1. **Blinding (each client, locally).** Client *i* computes a digest for every element of its
   set and keeps a private lookup table `Tᵢ : digest ↦ element`. The table never leaves the
   client and is the only thing that can invert a digest.
2. **Submission.** Each client sends only the digests, in **shuffled** order. Shuffling matters:
   if the digests arrived in set order, their positions would leak the ordering of the
   underlying elements, and with a sorted set that leaks their relative magnitude.
3. **Intersection (Server).** The Server, which holds no set and performs no inversion,
   computes the set intersection `I = D₁ ∩ D₂` of the two digest lists and returns `I` to both
   clients.
4. **Recovery (each client, locally).** Client *i* maps each digest in `I` back through its own
   table `Tᵢ`. Because `H` is deterministic, a shared element produces an identical digest at
   both clients, so `I` contains exactly the digests of `X₁ ∩ X₂`, and each client recovers
   `{ Tᵢ[d] : d ∈ I } = X₁ ∩ X₂`.

**Why no element reaches the Server.** The Server receives only 256-bit digests and returns a
subset of what it was given. Pre-image resistance means a digest cannot be inverted by
computation alone. Section A.5 shows that this is *not* the same as saying the Server learns
nothing, and fixes the gap.

*(≈380 words)*

## A.4 Implementation and testing (3 marks)

The protocol is implemented in Python 3 with the standard library only. `psi/server.py` is a
real HTTP server (`ThreadingHTTPServer`) that implements steps 3 and the relay; `psi/client.py`
is the client, run twice concurrently; `psi/run_experiments.py` starts the Server and drives
both runs. Comments marked `PROTOCOL STEP n` identify each step of A.3 in the code. The Server
logs every message it receives, and that log is reproduced verbatim below, which is what makes
the privacy analysis in A.5 evidence-based rather than assumed.

### (i) Run 1 — the given sets

Client 1 = `{1, 2, 5, 9, ID}`, Client 2 = `{5, 8, 11, ID}`, `ID = 240000000`.

**Messages received by the Server** (session `run1`, copied from `results/transcript.txt`):

```
[ 1] Server <-- client1   BLINDED_SET   mode=plain  count=5
       ecf2de5604e9c6182e7216c895ec99794da0a8100ee978ef94492316155c67b0
       443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e
       96dcfae20d4e26466b1f7dace43d95372c97aeea149dfa30d7c16f0d2261b9ee
       e260cd620dacae93083601390766659bd8f9d18001c1b1f0db128f7a381362e5
       99e2d08e26e0cf553853271a4d51fa24a533cc7cc262cdbdce98dd64901dddab
[ 2] Server <-- client2   BLINDED_SET   mode=plain  count=4
       e260cd620dacae93083601390766659bd8f9d18001c1b1f0db128f7a381362e5
       443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e
       d78bd3d40637d1b405728f69a29ca85976e5e7824f1033e8c46967fe01d4767f
       ce21b7c354366862da6409a2087b7694374c3587843cfa0bd74e156213b05d41
[ 3] Server --> both clients   INTERSECTION   count=2
       443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e
       e260cd620dacae93083601390766659bd8f9d18001c1b1f0db128f7a381362e5
```

No raw set element appears anywhere in the Server's view.

**Clients' outputs**

```
[client1] INTERSECTION = [5, 240000000]
[client2] INTERSECTION = [5, 240000000]
```

Both clients independently inverted the two returned digests through their own tables and
obtained the same answer, `{5, ID}`, which is correct.

### (ii) Run 2 — Client 2's set modified

Client 2's set was changed from `{5, 8, 11, ID}` to `{2, 8, 11, ID}`: the shared element `5`
was removed and `2`, which Client 1 holds, was added. Client 1's set was left unchanged.

```
[client1] INTERSECTION = [2, 240000000]
[client2] INTERSECTION = [2, 240000000]
```

**Explanation.** The output changed from `{5, ID}` to `{2, ID}`, exactly as the sets dictate.
`5` disappeared because Client 2 no longer holds it, so its digest
`443d7581…` is now in `D₁` only and fails the Server's set intersection. `2` appeared because
both clients now hold it, so both produced the identical digest `ecf2de56…` and it survived the
intersection. `ID` is still common to both sets, so `e260cd62…` is returned again — and it is
*the same digest string as in Run 1*, which is the determinism the protocol relies on and also,
as A.5 shows, a weakness. The digest of an element depends only on the element, not on who sent
it or when, which is why equality can be tested at all.

*(≈300 words excluding listings)*

## A.5 Privacy analysis (3 marks)

### What the Server can learn from the messages in A.4

Even though no element is sent in the clear, the Server's view is not empty. From the log above
it directly learns: the **cardinality** of each client's set (5 and 4); the **size of the
intersection** (2); and, because digests are deterministic and unkeyed, **which digests the two
clients have in common** and which are unique to one of them. Across sessions it learns more:
digest `e260cd62…` appears in Run 1, Run 2 and in both clients' sets, so the Server can **link**
the same element across runs and across clients without knowing what it is. If it ran the
protocol with many clients it could build a profile of who shares which (still unidentified)
elements — a social graph by correlation.

### Could the Server recover elements by hashing candidate values? Yes.

SHA-256 is a public, unkeyed, deterministic function, so the Server can compute it on any
candidate it likes and compare. Pre-image resistance says nothing useful here because the input
domain is minuscule: small integers, and a student number of a known fixed format. This is a
dictionary attack, not a break of SHA-256.

`psi/attack_bruteforce.py` implements exactly this attack, using only the digests the Server
legitimately received. Measured output (`results/transcript.txt`):

```
Phase 1: hash every integer in [0, 10000) and compare.
         10,000 candidates hashed in 0.01s (1,421,700 hashes/second, single-threaded Python)
client1: recovered 4/5 elements
    96dcfae20d4e26466b1f7dac...  ->  1
    ecf2de5604e9c6182e7216c8...  ->  2
    443d7581c97e9580bbf394b5...  ->  5
    99e2d08e26e0cf553853271a...  ->  9
client2: recovered 3/4 elements
    443d7581c97e9580bbf394b5...  ->  5
    ce21b7c354366862da6409a2...  ->  8
    d78bd3d40637d1b405728f69...  ->  11
Phase 2: searching 240,000,000..240,099,999
    e260cd620dacae9308360139...  ->  240000000   <-- STUDENT NUMBER RECOVERED
RESULT: 7/7 distinct digests inverted.
```

**Concrete example.** Digest `443d7581c97e9580bbf394b5fdc2a4a61405bceb987c6b1e4f4b6e2ee56c6f9e`
is `SHA-256("CSC8214-PSI-v1|5")`. The Server computed that in under a microsecond by trying
`x = 5`, and thereby learned that Client 1 and Client 2 both hold the element `5` — not merely
that they share *something*. Every element of both sets, including the student number, was
recovered in well under a second. Even with no hint about the student-number prefix, the whole
9-digit space is 10⁹ candidates: about 0.2 hours in this unoptimised Python and seconds on a
GPU. **The protocol of A.3 therefore protects the elements from a network eavesdropper but
not from the Server.**

### One possible improvement, and its limitations

**Improvement: replace the unkeyed hash with a keyed one, under a key the Server does not
hold.** The two clients first run a Diffie–Hellman exchange (2048-bit MODP group, RFC 3526),
*relayed by* the Server, and derive `k = KDF(g^{ab})`. They then send
`HMAC-SHA256(k, T‖x)` instead of `SHA-256(T‖x)`. Equality still holds for equal elements, so the
Server's intersection step is unchanged, but the Server now cannot compute the digest of *any*
candidate, because it only ever saw `g^a` and `g^b` and deriving `g^{ab}` is the computational
Diffie–Hellman problem. This is Run 3 in the implementation (`--mode hmac`), and the same attack
script against it reports:

```
=> the Server cannot compute the digest of ANY candidate value.
=> 0 of the elements can be recovered by hashing candidates.
RESULT: attack fails.
```

**Limitations of the improvement.**

1. **It only moves the trust boundary; it does not remove it.** The key is shared between the
   two clients, so *Client 1 can now brute-force Client 2's non-matching digests* exactly as the
   Server could before. Against a curious peer rather than a curious server, nothing has been
   gained. A protocol that fixes this — Diffie–Hellman PSI, where each party blinds with its own
   secret exponent, or an OT-based PSI — is needed for mutual protection.
2. **The Server still learns the metadata.** Set sizes, intersection size and the *pattern* of
   matches within a session are unchanged. Within a single session the Server can still link
   repeated digests, and if the clients reuse `k` across sessions it can link across them too;
   the key must be fresh per session to prevent that.
3. **The key exchange is unauthenticated.** The Server relays the public values, so it can mount
   a man-in-the-middle attack, giving each client its own key, learning both sets' digests under
   keys it chose, and brute-forcing them after all. The DH exchange must be authenticated
   (signatures or a pre-shared credential) out of band, which introduces a key-management burden
   the plain protocol did not have.
4. **Nothing hides the output.** Both clients still learn the intersection itself, which is
   inherent to PSI; if the intersection is a single element, each client learns a fact about the
   other with certainty.

---

# Part B — Blockchain and Smart Contracts (25 marks)

## B.1 Smart contract concept (2 marks)

A smart contract is a program stored on a blockchain that executes automatically when it is
called, and whose execution and results are replicated and verified by every node in the
network. It is "a contract" in the sense that it encodes an agreement — *if these conditions
are met, then this transfer happens* — and "smart" in the sense that it enforces that agreement
itself, in code, rather than relying on a court or an intermediary to do so.

In practice a contract has an address, persistent storage (state variables), a balance of the
chain's native currency, and functions that external accounts or other contracts can call by
sending a transaction. A call is a transaction like any other: it is ordered by consensus,
every node runs the same bytecode on the same inputs, and the resulting state change is agreed
by all of them. Because the state transition is deterministic and publicly replayable, no party
has to trust the counterparty or the operator — they only have to trust the code and the chain.

The properties that follow are the point of the technology. Execution is **autonomous** (no
operator decides whether to honour it), the outcome is **transparent and auditable** (anyone can
read the code and the history), and the deployed code is **immutable** (it cannot be quietly
changed afterwards). Transactions are **atomic**: a call either completes fully or reverts and
leaves no trace but the gas consumed.

The same properties are the risks. Immutable code cannot be patched when it turns out to be
wrong, and an irreversible transfer cannot be recalled, which is why bugs in smart contracts
have cost hundreds of millions of pounds.

*(≈280 words)*

## B.2 Comparison and development environment (3 marks)

**The online compiler used in the lab is Remix IDE (`https://remix.ethereum.org`)** — a
browser-based Solidity IDE with an integrated compiler, a JavaScript VM for deploying and
calling contracts without spending real ether, a debugger and a static-analysis plugin.

| | Traditional contract | Smart contract |
|---|---|---|
| Expressed in | Natural language | Executable code (e.g. Solidity) |
| Interpreted by | Humans; courts resolve ambiguity | The EVM, deterministically; no ambiguity, and no discretion either |
| Enforcement | After the fact, by a court, at cost and delay | At execution time, automatically |
| Intermediaries | Lawyers, banks, escrow agents | None; the chain is the escrow |
| Amendable? | Yes, by agreement of the parties | No — deployed bytecode is immutable |
| Errors | Can be read down, rectified or set aside | Execute as written; "the code is the contract" |
| Cost | Legal fees | Gas, paid per operation |
| Scope | Any obligation that can be described | Only what is on-chain and deterministic |

The deepest difference is that a traditional contract states *intent* and leaves enforcement to
a system that can apply judgement, while a smart contract *is* the enforcement and has no
judgement at all. A traditional contract containing a typo in a payment clause will usually be
rectified; a smart contract containing the same typo will pay the wrong amount, every time,
with no recourse. A second real difference is scope: a smart contract can only act on facts it
can see on-chain, so anything about the physical world ("goods delivered in good condition")
has to be supplied by a trusted oracle, which reintroduces exactly the trusted third party the
design set out to remove.

*(≈260 words)*

## B.3 Security considerations (5 marks)

Smart contract code is public, immutable once deployed, and directly controls money, so the
consequences of a defect are immediate and irreversible. Using the crowdfunding contract of
B.4 as the running example, the main considerations are:

**Reentrancy.** When a contract sends ether with `call`, the recipient's code runs before the
sending function finishes. If the recipient calls back into the sending function while its
state has not yet been updated, the check that was supposed to prevent a second payout still
passes. This is what drained The DAO of about 3.6 million ETH in 2016. The defence is the
**checks-effects-interactions** pattern: validate, then write state, then make the external
call last. In `withdraw()` the line `withdrawn = true;` is executed *before*
`beneficiary.call{value: amount}("")`, so a re-entrant call hits `AlreadyWithdrawn` and
reverts. The test in `scripts/test_crowdfunding.js` deploys a hostile beneficiary that does
exactly this, and confirms the attack fails and the contract pays out once.

**Access control.** Anyone can call any `public`/`external` function. Payout must be restricted
to the beneficiary (`onlyBeneficiary`, comparing `msg.sender`, which the EVM sets and a caller
cannot forge). `tx.origin` must never be used for this, as it is phishable.

**Arithmetic.** Before Solidity 0.8, `totalRaised += msg.value` could wrap around and reset the
raised total. From 0.8 onwards arithmetic reverts on overflow by default.

**Trusting `address(this).balance`.** A contract can be force-fed ether by `selfdestruct`,
which bypasses `receive()`. A campaign whose target test read the raw balance could be made to
"succeed" with no genuine contributions, so the contract tracks `totalRaised` in its own
variable instead.

**Unchecked return values and gas.** `send`/`transfer` cap the recipient at 2300 gas and fail
for contract beneficiaries; `call` returns a boolean that must be checked, which the contract
does (`if (!ok) revert TransferFailed();`).

**Denial of service and griefing.** Paying out in a loop over contributors lets one reverting
recipient block everyone; the pull-over-push pattern avoids it.

**Front-running and visibility.** Pending transactions are public in the mempool and can be
reordered by miners/validators; and `private` only restricts other *contracts*, never human
readers — all storage is publicly readable.

**Process.** Testing (32 cases here), static analysis (Slither, Remix's analyser), and
independent audit before deployment, because the code cannot be patched afterwards.

*(≈300 words excluding the heading words)*

## B.4 Crowdfunding contract (10 marks)

Full source: `contracts/Crowdfunding.sol`. The four required behaviours map to the code as
follows.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Crowdfunding {
    // REQUIREMENT 2: beneficiary and target, fixed at deployment.
    // `immutable` means not even the deployer can rewrite them later.
    address payable public immutable beneficiary;
    uint256 public immutable target;

    // Tracked explicitly, NOT read from address(this).balance, so that a
    // selfdestruct cannot push the campaign over its target artificially.
    uint256 public totalRaised;
    mapping(address => uint256) public contributions;

    // REQUIREMENT 4: the one-shot latch that makes withdrawal non-repeatable.
    bool public withdrawn;

    event ContributionReceived(address indexed contributor, uint256 amount, uint256 totalRaised);
    event TargetReached(uint256 totalRaised);
    event FundsWithdrawn(address indexed beneficiary, uint256 amount);

    error ZeroContribution();
    error NotBeneficiary(address caller);
    error TargetNotReached(uint256 raised, uint256 required);
    error AlreadyWithdrawn();
    error TransferFailed();

    constructor(address payable _beneficiary, uint256 _target) {
        require(_beneficiary != address(0), "beneficiary must not be the zero address");
        require(_target > 0, "target must be greater than zero");
        beneficiary = _beneficiary;
        target = _target;
    }

    // msg.sender is set by the EVM and cannot be spoofed by the caller.
    modifier onlyBeneficiary() {
        if (msg.sender != beneficiary) revert NotBeneficiary(msg.sender);
        _;
    }

    // REQUIREMENT 1: accept contributions.
    function contribute() public payable {
        if (msg.value == 0) revert ZeroContribution();
        bool wasBelowTarget = totalRaised < target;
        contributions[msg.sender] += msg.value;   // 0.8+ reverts on overflow
        totalRaised += msg.value;
        emit ContributionReceived(msg.sender, msg.value, totalRaised);
        if (wasBelowTarget && totalRaised >= target) emit TargetReached(totalRaised);
    }

    // Plain transfers count as contributions, so funds are never trapped.
    receive() external payable { contribute(); }

    // REQUIREMENTS 3 and 4, in checks-effects-interactions order.
    function withdraw() external onlyBeneficiary {
        if (totalRaised < target) revert TargetNotReached(totalRaised, target); // CHECK
        if (withdrawn) revert AlreadyWithdrawn();                               // CHECK
        withdrawn = true;                                                       // EFFECT
        uint256 amount = address(this).balance;
        (bool ok, ) = beneficiary.call{value: amount}("");                      // INTERACTION
        if (!ok) revert TransferFailed();
        emit FundsWithdrawn(beneficiary, amount);
    }

    function targetReached() external view returns (bool) { return totalRaised >= target; }
    function remaining() external view returns (uint256) {
        return totalRaised >= target ? 0 : target - totalRaised;
    }
    function balance() external view returns (uint256) { return address(this).balance; }
}
```

### How a withdrawal is handled **before the target is reached**

`withdraw()` evaluates its checks in order. The caller is first required to be the beneficiary;
anyone else is rejected with `NotBeneficiary`. The beneficiary then hits
`if (totalRaised < target) revert TargetNotReached(totalRaised, target);`. Because this is a
`revert`, the entire transaction is rolled back atomically: no state is changed, no ether moves,
the `withdrawn` flag is untouched, and the only cost is the gas spent. The revert carries both
figures, so the caller's wallet can display exactly how much is still missing. Contributions are
therefore safe in the contract until the target is genuinely met. Tested: *"beneficiary cannot
withdraw below the target → `TargetNotReached`"* and *"funds untouched after failed withdrawals
→ 8.0 ETH"*.

### How a withdrawal is handled **after the funds have already been withdrawn**

The first successful `withdraw()` sets `withdrawn = true` **before** sending anything. A second
call therefore passes the access-control and target checks but reverts with `AlreadyWithdrawn`,
and again nothing moves. The ordering is what matters: because the flag is written before the
external call, even a beneficiary contract that re-enters `withdraw()` from inside its
`receive()` function — the DAO attack — meets the same closed latch, so the funds can leave the
contract exactly once. The latch is permanent: money contributed *after* a withdrawal also
cannot be withdrawn, which is correct for "no double withdrawal" but is a real functional
limitation, discussed in B.5.

### Test results

`npx hardhat run scripts/test_crowdfunding.js` — **32 passed, 0 failed**
(full output in `results/crowdfunding_tests.txt`). Covered: deployment validation; contributions
by several accounts and by plain transfer; rejection of zero-value contributions; withdrawal
blocked before the target for both the beneficiary and a stranger; `TargetReached` emitted
exactly once, on the crossing contribution; over-funding accepted; the full balance reaching the
beneficiary; the contract emptied; the second withdrawal rejected; and a hostile re-entrant
beneficiary failing to extract a second payout.

## B.5 Limitations and improvements (5 marks)

**Limitation 1 — functionality: there is no deadline and no refund, so contributors' money can
be locked forever.** If the campaign stalls below its target, `withdraw()` always reverts with
`TargetNotReached` and there is no other path out of the contract: every contribution is
permanently frozen. The same latch also strands money that arrives *after* a successful
withdrawal — the test confirms 2 ETH contributed late is stuck. *Improvement:* add a `deadline`
set in the constructor and a `refund()` function that, after the deadline and only if the
target was missed, lets each contributor withdraw their own recorded `contributions[msg.sender]`
using the **pull-payment** pattern from the lab (zero the balance first, then send). *Trade-off:*
this adds state and a second money-moving path, so it widens the attack surface — refunds must
be reentrancy-safe and must not be claimable twice — and it makes the campaign depend on
`block.timestamp`, which validators can nudge by a few seconds. It also means contributors must
actively claim, and any who never do still lose their funds.

**Limitation 2 — privacy: every contribution is public, permanent and linkable.** `contribute()`
writes the contributor's address and exact amount to public storage and emits an event, so
anyone can see who donated, how much and when, and can link it to that address's entire history
— which is how a donation to a politically sensitive campaign becomes a permanent public record.
*Improvement:* replace the stored address with a **commitment** `H(secret‖amount)` and let the
contributor prove membership later with a zero-knowledge proof (the zk-SNARK approach covered in
the lectures), or accept contributions through a privacy-preserving pool. *Trade-off:* ZK
verification is expensive in gas, raising the cost per contribution, and it removes the
transparency that lets donors verify the campaign is honest; it also makes compliance with
anti-money-laundering duties considerably harder.

*(≈300 words)*

---

# Part C — Using Security Tools Correctly (10 marks)

## C.1 Hashing and encryption (5 marks)

**No. A hash function must not be used to encrypt sensitive information, because hashing is not
encryption.** Encryption is a reversible, keyed transformation: the whole point is that the
holder of the key can recover the plaintext. A cryptographic hash is a deterministic, keyless,
one-way compression to a fixed-length digest. There is no decryption function and no key, so
information "encrypted" with a hash cannot be recovered by its legitimate owner either. Since
SHA-256 maps arbitrarily long inputs to 256 bits, information is irretrievably destroyed by
construction. Confidentiality requires an authenticated cipher such as AES-GCM or ChaCha20-
Poly1305 with a properly managed key.

The second, more dangerous error is assuming that a digest *hides* its input. It only does so
when the input is unpredictable. Because the hash function is public and deterministic, anyone
can hash candidate values and compare digests, so for any low-entropy input — a password, a
postcode, a date of birth, an NHS number, a student number — the "protection" is defeated by a
dictionary or exhaustive search. Part A.5 of this report demonstrates precisely that: every
SHA-256 digest sent to the PSI Server, including the student number, was inverted in under a
second.

Hashes have proper uses: integrity checking, digital signatures, commitments, and deriving
look-up keys. For passwords specifically, the correct tool is not a plain hash either but a
*slow, salted* password-hashing function — Argon2id, scrypt or bcrypt — where the per-user salt
defeats precomputed rainbow tables and the deliberate cost makes large-scale guessing
uneconomic. If the data must be both confidential and recoverable, encrypt it; if it must be
verifiable but never recovered, hash it correctly; the two requirements are not interchangeable.

*(≈290 words)*

## C.2 Password recovery in Lab 1 (Task 3) (5 marks)

> *Framed from the standard Lab 1 Task 3 setup — a small published list of candidate passwords,
> each transformed with the same unkeyed, deterministic scheme, and a single ciphertext `X` to
> be matched. Adjust the specifics if your lab sheet differs.*

It was possible to identify exactly which password had been encrypted because the task combined
three properties, each harmless alone but fatal together.

**First, the transformation was deterministic and used no randomisation.** The same plaintext
under the same key always produced the same ciphertext `X`: there was no per-record salt, no
random IV, and no nonce. Consequently `X` acts as a stable fingerprint of its plaintext, and
equality of ciphertexts implies equality of plaintexts. This is exactly the weakness of ECB
mode and of unsalted password hashing.

**Second, the algorithm and its parameters were public.** Kerckhoffs's principle applies in
reverse here: because the scheme (and in the lab, the key or the fact that no key was involved)
was known, anyone could compute the transformation themselves in the forward direction. Nothing
had to be inverted — `X` was never "decrypted".

**Third, and decisively, the search space was tiny.** The candidate passwords were drawn from a
small published list. The attack is therefore: for each candidate `p` in the list, compute
`E(p)` and test whether it equals `X`. The first match identifies the password uniquely, because
the output space (2²⁵⁶ for SHA-256) is vastly larger than the candidate space, so an accidental
collision is negligibly unlikely. A handful of operations sufficed.

The lesson is that the strength of the primitive was never the issue. A perfectly sound cipher
or hash still leaks the plaintext when the plaintext is guessable and the transformation is
deterministic and unsalted. The fixes are to add a unique random salt or IV to each record —
destroying the fingerprint, so identical passwords no longer produce identical outputs — and to
use a deliberately slow KDF (Argon2id, bcrypt) so that each guess costs real time.

*(≈300 words)*

---

# Part D — Federated Learning and Privacy-Preserving Data Cleaning (10 marks)

## D.1 Federated learning (5 marks)

**How it supports the two hospitals.** In federated learning the data never moves; the model
does. A coordinating server initialises a shared model and sends its current parameters to both
hospitals. Each hospital trains that model locally, on its own patient records, behind its own
firewall, for a few epochs, and sends back **only the resulting parameter updates** (weights or
gradients). The server aggregates the two updates — typically a weighted average, Federated
Averaging — to produce an improved global model, and the cycle repeats until convergence. Both
hospitals end up with a model trained effectively on the union of their patients, while every
patient record stays in the hospital that holds it. This matters clinically as well as legally:
each hospital alone may have too few cases of a rare condition to train a usable model, and
federated learning gives them the statistical power of the combined cohort.

**Privacy benefit.** No raw patient record is ever transmitted or centralised. There is no
pooled database to breach, to subpoena or to misuse, and each hospital remains the sole
controller of its own data, which makes the arrangement far easier to justify under the UK GDPR
and the common-law duty of confidentiality.

**Privacy risk that remains.** Model updates are *derived from* the training data and leak
information about it. Gradients can be inverted to reconstruct recognisable training examples
(gradient-inversion attacks), and membership-inference attacks can reveal whether a particular
individual's record was in the training set — in a hospital, that alone discloses that the
person was a patient, and often which condition they have. Small or homogeneous cohorts leak
most. Mitigations are differential privacy (clipping updates and adding calibrated noise),
secure aggregation so the server sees only the sum of the two updates and never either one, and
limiting the number of rounds — each at some cost in accuracy.

*(≈300 words)*

## D.2 Privacy-preserving data cleaning (5 marks)

The two hospitals want to fill missing values using each other's records, which first requires
knowing *which patients they have in common* — the same problem as Part A. The method from the
data-cleaning lab is **privacy-preserving record linkage followed by targeted exchange, rather
than data pooling.**

**Step 1 — agree the matching.** Both hospitals canonicalise their identifying fields (NHS
number, or surname + date of birth + postcode, normalised identically on both sides) and
compute a **keyed** digest of each, `HMAC-SHA256(k, identifier)`, under a secret key `k` agreed
between the two hospitals only. They exchange the shuffled digest lists and intersect them: this
is exactly the PSI protocol of A.3 with the A.5 improvement. The key is essential — an NHS
number is a low-entropy, structured identifier, so an unkeyed hash of it is recoverable by
brute force in the way A.5 demonstrated. Where approximate matching is needed because records
contain typos, the lab's Bloom-filter encoding of character bigrams supports similarity
comparison on the encoded values, at the price of some leakage from set-bit patterns.

**Step 2 — fill the gaps.** Only for the matched patients does either hospital request a
specific missing field, and only that field. Where even the field value is too sensitive to
expose, the imputation can be computed under homomorphic encryption or secure two-party
computation, so the requester receives the filled value without the holder learning which record
it belonged to.

**How this differs from sending both datasets to a central server.** In the central model both
hospitals disclose *every* record about *every* patient, including the non-overlapping majority
who are irrelevant to the task, to a third party that becomes a single point of failure and a
new data controller. Here, nothing is disclosed about non-matching patients, no third party ever
holds either dataset, the key never leaves the two hospitals, and the exchange is limited to the
specific missing values — data minimisation and purpose limitation enforced by cryptography
rather than by contract.

*(≈300 words)*
