# CSC8214 System Security: Assignment and Report

**Student number (ID):** `260452597`

All outputs quoted below were produced by `python3 psi/run_experiments.py` and
`npx hardhat run scripts/test_crowdfunding.js`, and are copied verbatim from
`results/transcript.txt` and `results/crowdfunding_tests.txt`. Source code is in Appendix A.

---

# Part A: Private Set Intersection

## A.1 Concept

Private Set Intersection (PSI) is a cryptographic protocol that lets mutually distrustful
parties compute the intersection of their private sets such that nothing about the sets'
elements, beyond the result, is revealed. If Alice holds `{1, 2, 3}` and Bob holds
`{1, 3, 4, 5, 9}`, both may learn `{1, 3}`, but during and after the computation Bob must not
learn `2` and Alice must not learn `4`, `5` or `9`.

Computing an intersection would be trivial if the parties could hand their sets to a trusted
third party. PSI is non-trivial precisely because no such party exists, and neither owner knows
what the other holds.

PSI protocols divide into two settings. In **traditional PSI** the only participants are the
set owners, who interactively compute the result from their local sets and repeat that work
every time. In **delegated PSI** the owners encode their sets and send the encodings to a server, typically cloud, which performs the computation and/or storage on their behalf. Delegated
protocols divide further into **one-off delegation**, where the owners re-encode their data for
each computation, and **repeated delegation**, where one outsourcing supports any number of
later intersections. A.3's protocol is a delegated PSI with one-off delegation.

Security is stated against an adversary type. A **passive** (semi-honest) adversary is the
weakest: it follows the protocol but is curious, so a PSI secure against it need only satisfy
privacy. An **active** (malicious) adversary is the strongest: it may deviate from the
protocol's instructions, so the PSI must additionally guarantee the result's correctness, in
the sense that deviation producing an incorrect result is detected. Common building blocks are
hash functions, pseudorandom functions (PRFs), homomorphic encryption and polynomial
representations for security, and hash tables and Bloom filters for efficiency.

## A.2 Application

A real-world application is **Apple's proposed system to combat Child Sexual Abuse Material**
(2021), which used PSI to check images on a user's device against a database of known illegal
images held by child-protection organisations.

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
revealed; it cannot decide whether computing that intersection is legitimate. The scheme was
withdrawn in 2022 after sustained criticism that the same machinery, once deployed, could be
repointed at any other database. Cryptography constrained what was learned, not what could
later be asked.

## A.3 Protocol design

**Parties and inputs.** Client 1 holds `X₁ = {1, 2, 5, 9, ID}`; Client 2 holds
`X₂ = {5, 8, 11, ID}`, where `ID` is my student number. The Server has no input set. This is a
**delegated PSI** with one-off delegation: the clients encode their sets, the Server compares
them, and both clients learn `X₁ ∩ X₂` without sending any raw element.

**Threat model.** The Server is **passive (semi-honest)**: it follows the protocol but is
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
2. **Submission.** Each client sends only the digests, in **shuffled** order. Shuffling matters:
   in set order, a digest's position would leak the ordering of the underlying elements.
3. **Intersection (Server).** The Server, holding no set of its own, computes `I = D₁ ∩ D₂` and
   returns `I` to both clients.
4. **Recovery (each client, locally).** Client *i* maps each digest in `I` back through `Tᵢ`.
   Because `H` is deterministic, a shared element yields an identical digest at both clients, so
   `I` holds exactly the digests of `X₁ ∩ X₂` and each client recovers it.

A.5 adds an optional **Step 0**, in which the clients agree a secret key before Step 1 and
replace `H` with a keyed function. The four steps are otherwise unchanged, and the code comments
are numbered to match.

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
**cardinality** of each set (5 and 4), the **size of the intersection** (2), and, because
digests are deterministic and unkeyed, **which digests the two clients share** and which are
unique to one of them. Across sessions it learns more: digest `7171a8e2…` appears in Run 1, Run
2 and in both clients' sets, so the Server can **link** the same element across runs and across
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
the evidence supports is the single-thread one, and it is already far too low. **The protocol
of A.3 protects the elements from a network eavesdropper but not from the Server.**

### One possible improvement, and its limitations

**Improvement: blind with a pseudorandom function keyed by a secret the two clients share,
rather than with an unkeyed hash.** In Step 0 the clients run a Diffie–Hellman exchange, relayed
by the Server, and derive `k = KDF(g^{ab})`. They then send `HMAC-SHA256(k, T‖x)`, a PRF keyed
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

A contract formalises a relationship and contains a set of promises made between principals. A
**smart contract**, a term put forward by Nick Szabo in 1994, provides new ways to formalise and
secure digital relationships, using cryptographic and other security mechanisms to stop
algorithmically specifiable relationships being breached and to ensure the agreed terms are
satisfied.

On a blockchain, a smart contract is a program stored and executed on the chain, whose code
captures the logic of the contractual clauses between the parties. The code is run by the
network's nodes: they process and verify the transaction, run the called contract, and reach
consensus on the new state. We can therefore treat a contract as being executed by a trusted
global machine that honestly performs every instruction, even though no individual machine is
trusted.

The effect is to **minimise trust**, and often operating costs: the parties need not trust one
another, nor an intermediary to hold the money or decide whether to honour the agreement. A
contract is passive: it cannot invoke itself, and acts only when an account calls it. Changing
its state requires a new transaction published to the network.

The same properties are the risks. Deployed code is immutable, so a mistake cannot be patched,
and contracts usually have no private state, which buys transparency at the cost of privacy.

## B.2 Comparison and development environment

**The online compiler used in the lab is Remix (`remix.ethereum.org`)**, a browser-based IDE to
write, compile and debug Solidity contracts, with a built-in test chain (set the Environment
option to the JavaScript VM, which current versions of Remix label the **Remix VM**) so that
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
rectified; a smart contract with the same typo pays the wrong amount every time. Deployed
bytecode cannot be edited, although upgradeable proxy patterns reach new logic through a fixed
address, at the cost of reintroducing a party who can change the rules.

A second difference is scope. A smart contract acts only on facts it can see on-chain, so
anything about the physical world must come from a trusted oracle, which reintroduces the
trusted third party the design set out to remove.

## B.3 Security considerations

Take the lab's `Donation` contract.

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
without `payable` the call would revert. The security questions appear once a withdraw function
lets the money leave again.

**Access control.** Any `public` function can be called by anyone, so a withdrawal path must
check its caller. `msg.sender` is set by the EVM and cannot be forged; `tx.origin` must never be
used, as it can be phished through an intermediate contract.

**Reentrancy.** When the contract sends Ether with `call`, the recipient's code runs *before*
the sending function finishes. If it calls back in while the state still says the funds are
unspent, the guard passes twice, which is how The DAO was drained in 2016. The defence is
**checks-effects-interactions**: validate, write state, call out last. In B.4
`withdrawn = true` executes before the `call`, so a re-entrant call reverts.

**Checking the return value.** `call` reports failure by returning `false`, so an unchecked
result silently loses funds. B.4 checks and reverts.

**Not trusting the raw balance.** `address(this).balance` can be inflated by `selfdestruct`,
bypassing `donate()`, so a campaign testing it could be pushed over its target with no genuine
donation. B.4 tracks its own total.

**Gas and denial of service.** Ethereum's language is Turing-complete, so a contract could make
the miners work forever, a denial-of-service attack. Gas forces termination: each operation has
an explicit cost, and a transaction costs Gas Limit × Gas Price. Work growing with the number of
contributors can exceed the limit, so each party should withdraw its own share.

**Process.** The lecture's lifecycle ends implementation with: test it many times, analyse its
security, let others review the code, because deployed code cannot be patched.

## B.4 Crowdfunding contract

Full source, `contracts/Crowdfunding.sol`:

<<<INCLUDE:contracts/Crowdfunding.sol:solidity>>>

**A design choice worth stating.** The funds always go to `beneficiary` regardless of who calls
`withdraw()`, so restricting the caller is not needed to protect the destination. The caller is
restricted anyway so that the beneficiary controls the *timing* of the payout, rather than
having a stranger trigger the transfer at an arbitrary moment.

### Withdrawal **before** the target is reached

`withdraw()` checks the caller is the beneficiary, then reaches
`if (totalRaised < target) revert TargetNotReached(totalRaised, target);`. The revert rolls the
whole transaction back atomically: no state changes, no Ether moves, `withdrawn` is untouched,
and the only cost is gas. The error carries both figures, so a wallet can show how much is still
missing. Contributions are therefore safe in the contract until the target is genuinely met.

### Withdrawal **after** the funds have already been withdrawn

The first successful `withdraw()` sets `withdrawn = true` **before** sending anything, so a
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

`npx hardhat run scripts/test_crowdfunding.js` gives **33 passed, 0 failed**. Full output:

<<<INCLUDE:results/crowdfunding_tests.txt:text>>>

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

**No. A hash function must not be used to encrypt sensitive information, because hashing is not
encryption.** An encryption scheme uses a key: `Encrypt_k(m) = C`, and the secret key allows the
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

Task 3 demonstrated the misuse `cipher = SHA256(plaintext)`, encryption replaced by a bare
hash. We were given a ciphertext `X` and a list of four candidate passwords, and asked which had
been "encrypted". Hashing each candidate and comparing to `X` recovers the plaintext on the
third attempt (`scripts/lab1_task3_attack.py`):

<<<INCLUDE:results/lab1_task3_attack.txt:text>>>

The plaintext was `1989-Newcastle`. Three properties made this possible, and all three had to
hold together.

**No key and no randomness.** The task states that no secret key or randomness is used to
encrypt the message. Encryption provides confidentiality through a secret key and a random
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
Argon2id, whose per-record salt destroys the fingerprint. The lab's closing question, whether a
hash can encrypt such that you can later decrypt, answers itself: a one-way function has no
inverse.

---

# Part D: Federated Learning and Privacy-Preserving Data Cleaning

## D.1 Federated learning

**How it supports the two hospitals.** In federated learning the data never moves; the model
does. One round has four steps: the server sends the global model parameters to both hospitals;
each trains that copy locally for several local epochs on its own examples; each returns its
trained parameters, training sample count and scalar metrics, never the examples; and the
server combines the replies with **Federated Averaging (FedAvg)**, a sample-count-weighted
average, so a hospital with more examples gets a larger share of the weight. With `nₖ`
the number of training examples at client *k*, `w ← Σₖ (nₖ / Σⱼ nⱼ) wₖ`. If A returns 0.4 after
training on 100 examples and B returns 0.8 on 300, the result is 0.7, not the unweighted 0.6.
Repeating the round gives both a model shaped by the union of their patients.

**Privacy benefit.** Raw patient records stay in the hospital that holds them: there is no
pooled database to breach or subpoena, and each hospital keeps control over access to its own
records while contributing to the shared model.

**Privacy risk that remains.** Keeping examples local does not guarantee privacy: shared
updates still reveal information about the data. Zhu et al. showed training examples can
sometimes be reconstructed from shared gradients *under their experimental conditions*, and
membership inference can reveal whether a person's record was used, which in a hospital
discloses that they were a patient.

The usual mitigations are secure aggregation, which hides individual updates from the server,
and differential privacy, which bounds any one record's influence. **With two participants
secure aggregation gives little protection against the other hospital**: A knows its own update,
so subtracting it from the aggregate recovers B's exactly. Here differential privacy carries
most of the weight, at a cost in accuracy.

## D.2 Privacy-preserving data cleaning

The method studied is **secure mean imputation using secure aggregation**, which replaces
pooling with protected totals.

**The plaintext baseline.** Writing `mᵢ = 1` when a value is observed, a central server pools
the records and computes `μ = Σᵢ xᵢmᵢ / Σᵢ mᵢ`, which requires receiving every record.

**The secure version.** For the field with gaps, say creatinine, each hospital *k* computes
`sₖ = Σᵢ xₖᵢ mₖᵢ`, the sum of the values it observed, and `nₖ = Σᵢ mₖᵢ`, how many it observed.
Only those protected totals leave the site. Under secure aggregation the coordinator obtains
`S = Σₖ sₖ` and `N = Σₖ nₖ` without seeing either contribution, computes `μ = S / N` and returns
it; each hospital fills its own gaps locally with `μ`. Secure aggregation matches the additive
part exactly, so the imputed value is the same; the coordinator never sees a record.

**Worked example.** Hospital A observes 80, 100 and 120, so `s_A = 300`, `n_A = 3`. Hospital B
observes 90 and 110, so `s_B = 200`, `n_B = 2`. Then `S = 500`, `N = 5`, `μ = 100`.

**How this differs from a central server.** In the plaintext approach the server receives every
record, becomes a new data controller and a single point of failure, and sees the patients
irrelevant to the imputation. Here it sees two totals, and records never leave the hospital.

**Limitations.** The aggregate itself is still revealed, and secure aggregation supports only
counts, sums and means. A median needs secure ordering, and regression or k-nearest-neighbour
imputation needs full MPC, which is markedly more expensive. More sharply, **with two hospitals
the aggregate leaks**: knowing `μ` and `N`, Hospital A computes `S − s_A = s_B` and
`N − n_A = n_B`, learning B's sum, count and local mean exactly. Secure aggregation protects
against the coordinator here, not against the only other participant.

---

# Appendix A: Source code

## A.1 `psi/common.py`

<<<INCLUDE:psi/common.py:python>>>

## A.2 `psi/server.py`

<<<INCLUDE:psi/server.py:python>>>

## A.3 `psi/client.py`

<<<INCLUDE:psi/client.py:python>>>

## A.4 `scripts/test_crowdfunding.js`

<<<INCLUDE:scripts/test_crowdfunding.js:javascript>>>
