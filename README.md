# CSC8214 System Security — Assignment

The report to submit is **[report/CSC8214-Report.md](report/CSC8214-Report.md)**.

## Before anything else

Put your own student number in. Every output that contains `ID` depends on it.

```bash
python3 psi/run_experiments.py --student-id 240123456
```

Then update the student number at the top of the report and the digests quoted in
sections A.4 and A.5 from the freshly written `results/transcript.txt`.

## Part A — Private Set Intersection

| File | Role |
|---|---|
| `psi/common.py` | canonical encoding, SHA-256 / HMAC-SHA256 blinding, Diffie–Hellman |
| `psi/server.py` | the Server: relays DH public values, intersects digest lists, logs everything |
| `psi/client.py` | the Client: blinds its set, submits digests, inverts the answer locally |
| `psi/run_experiments.py` | starts the Server and runs Runs 1–3 plus both attacks |
| `psi/attack_bruteforce.py` | the Server trying to invert the digests it received (A.5) |

Everything is standard-library Python 3 — no `pip install` needed.

### Run everything at once (starts the Server for you)

```bash
python3 psi/run_experiments.py --student-id 240123456
```

Writes `results/transcript.txt`, `results/results.json` and `results/server_log_full.json`.

### Or run the Server and the two clients by hand

Start the Server:

```bash
python3 psi/server.py --port 8214
```

Then, in two more terminals:

```bash
python3 psi/client.py --client-id client1 --set 1,2,5,9,240123456 --session run1
```

```bash
python3 psi/client.py --client-id client2 --set 5,8,11,240123456 --session run1
```

Add `--mode hmac` to both clients for the A.5 improvement. Then run the attack against what
the Server collected:

```bash
python3 psi/attack_bruteforce.py --session run1 --id-hint 2401 --id-width 5
```

## Part B — Crowdfunding smart contract

| File | Role |
|---|---|
| `contracts/Crowdfunding.sol` | the contract (B.4) |
| `contracts/ReentrantBeneficiary.sol` | hostile beneficiary used to test the reentrancy defence |
| `scripts/test_crowdfunding.js` | 32 functional tests |

The contract is written for the Remix IDE (`https://remix.ethereum.org`) used in the lab —
paste `Crowdfunding.sol` in, compile with 0.8.26, and deploy on the JavaScript VM. The same
tests also run locally on Hardhat:

```bash
npm install
```

```bash
npx hardhat run scripts/test_crowdfunding.js
```

Last run: **32 passed, 0 failed** (`results/crowdfunding_tests.txt`).

## Results

| File | Contents |
|---|---|
| `results/transcript.txt` | Runs 1–3, the Server's message log, both brute-force attacks |
| `results/results.json` | the same data, machine-readable |
| `results/server_log_full.json` | every message the Server saw, all sessions |
| `results/crowdfunding_tests.txt` | contract test output |
