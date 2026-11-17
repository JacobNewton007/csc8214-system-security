/**
 * CSC8214 System Security - Assignment Question B.4
 *
 * Functional tests for Crowdfunding.sol, run on Hardhat's in-process EVM.
 *
 *   npx hardhat run scripts/test_crowdfunding.js
 *
 * The scenarios map directly onto the behaviour the question asks to be
 * explained: a withdrawal attempted before the target is reached, and a
 * withdrawal attempted after the funds have already been withdrawn.
 */

const { ethers } = require("hardhat");

let passed = 0;
let failed = 0;

function check(description, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${description}${detail ? "  [" + detail + "]" : ""}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${description}${detail ? "  [" + detail + "]" : ""}`);
  }
}

/** Run a transaction that is expected to revert and return the revert reason. */
async function expectRevert(description, promise, expectedError) {
  try {
    await promise;
    check(description, false, "transaction unexpectedly succeeded");
    return null;
  } catch (error) {
    const message = error.message || String(error);
    check(description, message.includes(expectedError), expectedError);
    return message;
  }
}

function eth(value) {
  return ethers.parseEther(String(value));
}

function fmt(wei) {
  return `${ethers.formatEther(wei)} ETH`;
}

async function main() {
  const [deployer, beneficiary, alice, bob, carol, mallory] = await ethers.getSigners();

  console.log("=".repeat(74));
  console.log("B.4  CROWDFUNDING CONTRACT - FUNCTIONAL TESTS");
  console.log("=".repeat(74));

  // -----------------------------------------------------------------------
  console.log("\n-- Deployment (REQUIREMENT 2: beneficiary and target recorded) --");
  const TARGET = eth(10);
  const campaign = await ethers.deployContract("Crowdfunding", [beneficiary.address, TARGET]);
  await campaign.waitForDeployment();
  const campaignAddress = await campaign.getAddress();
  console.log(`  contract    : ${campaignAddress}`);
  console.log(`  beneficiary : ${beneficiary.address}`);
  console.log(`  target      : ${fmt(TARGET)}`);
  check("beneficiary stored", (await campaign.beneficiary()) === beneficiary.address);
  // NB: ethers v6 uses `contract.target` for the contract's own address, so the
  // Solidity getter of the same name has to be reached via getFunction().
  check("target stored", (await campaign.getFunction("target")()) === TARGET);
  check("nothing raised yet", (await campaign.totalRaised()) === 0n);
  check("not withdrawn yet", (await campaign.withdrawn()) === false);

  await expectRevert(
    "deploying with a zero beneficiary is rejected",
    ethers.deployContract("Crowdfunding", [ethers.ZeroAddress, TARGET]),
    "beneficiary must not be the zero address"
  );
  await expectRevert(
    "deploying with a zero target is rejected",
    ethers.deployContract("Crowdfunding", [beneficiary.address, 0]),
    "target must be greater than zero"
  );

  // -----------------------------------------------------------------------
  console.log("\n-- Contributions (REQUIREMENT 1) --");
  await (await campaign.connect(alice).contribute({ value: eth(4) })).wait();
  console.log(`  alice contributed 4 ETH   -> totalRaised = ${fmt(await campaign.totalRaised())}`);
  await (await campaign.connect(bob).contribute({ value: eth(3) })).wait();
  console.log(`  bob   contributed 3 ETH   -> totalRaised = ${fmt(await campaign.totalRaised())}`);

  check("alice's contribution recorded", (await campaign.contributions(alice.address)) === eth(4));
  check("bob's contribution recorded", (await campaign.contributions(bob.address)) === eth(3));
  check("totalRaised is 7 ETH", (await campaign.totalRaised()) === eth(7));
  check("target not yet reached", (await campaign.targetReached()) === false);
  check("3 ETH still needed", (await campaign.remaining()) === eth(3));

  // A plain transfer with no calldata must also count as a contribution.
  await (await carol.sendTransaction({ to: campaignAddress, value: eth(1) })).wait();
  check("plain transfer handled by receive()", (await campaign.contributions(carol.address)) === eth(1));
  check("totalRaised is 8 ETH", (await campaign.totalRaised()) === eth(8));

  await expectRevert(
    "a zero-value contribution is rejected",
    campaign.connect(alice).contribute({ value: 0 }),
    "ZeroContribution"
  );

  // -----------------------------------------------------------------------
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
  check("funds untouched after failed withdrawals",
    (await ethers.provider.getBalance(campaignAddress)) === eth(8), fmt(eth(8)));

  // -----------------------------------------------------------------------
  console.log("\n-- Crossing the target --");
  const tx = await campaign.connect(carol).contribute({ value: eth(4) });
  const receipt = await tx.wait();
  const events = receipt.logs
    .map((log) => { try { return campaign.interface.parseLog(log); } catch { return null; } })
    .filter(Boolean)
    .map((e) => e.name);
  console.log(`  carol contributed 4 ETH   -> totalRaised = ${fmt(await campaign.totalRaised())}`);
  console.log(`  events emitted            : ${events.join(", ")}`);
  check("TargetReached emitted on the crossing contribution", events.includes("TargetReached"));
  check("target now reached", (await campaign.targetReached()) === true);
  check("over-funding accepted (12 ETH > 10 ETH target)", (await campaign.totalRaised()) === eth(12));

  // A second TargetReached must NOT be emitted by later contributions.
  const laterReceipt = await (await campaign.connect(alice).contribute({ value: eth(1) })).wait();
  const laterEvents = laterReceipt.logs
    .map((log) => { try { return campaign.interface.parseLog(log); } catch { return null; } })
    .filter(Boolean)
    .map((e) => e.name);
  check("TargetReached is not emitted twice", !laterEvents.includes("TargetReached"));

  // -----------------------------------------------------------------------
  console.log("\n-- Withdrawal AFTER the target is reached --");
  await expectRevert(
    "a stranger still cannot withdraw",
    campaign.connect(mallory).withdraw(),
    "NotBeneficiary"
  );

  const before = await ethers.provider.getBalance(beneficiary.address);
  const contractBalance = await ethers.provider.getBalance(campaignAddress);
  const wr = await (await campaign.connect(beneficiary).withdraw()).wait();
  const gasCost = wr.gasUsed * wr.gasPrice;
  const after = await ethers.provider.getBalance(beneficiary.address);

  console.log(`  contract held             : ${fmt(contractBalance)}`);
  console.log(`  beneficiary gained        : ${fmt(after - before + gasCost)} (net of ${fmt(gasCost)} gas)`);
  check("beneficiary received the full balance", after - before + gasCost === contractBalance);
  check("contract balance is now zero",
    (await ethers.provider.getBalance(campaignAddress)) === 0n);
  check("withdrawn flag is set", (await campaign.withdrawn()) === true);

  // -----------------------------------------------------------------------
  console.log("\n-- Withdrawal AFTER the funds have already been withdrawn (REQUIREMENT 4) --");
  await expectRevert(
    "the beneficiary cannot withdraw a second time",
    campaign.connect(beneficiary).withdraw(),
    "AlreadyWithdrawn"
  );
  // Even if new money arrives afterwards, the latch stays closed.
  await (await campaign.connect(bob).contribute({ value: eth(2) })).wait();
  await expectRevert(
    "late contributions cannot be withdrawn either (latch is permanent)",
    campaign.connect(beneficiary).withdraw(),
    "AlreadyWithdrawn"
  );
  check("the 2 ETH that arrived late is now stuck in the contract (see B.5)",
    (await ethers.provider.getBalance(campaignAddress)) === eth(2));

  // -----------------------------------------------------------------------
  console.log("\n-- Reentrancy: a hostile beneficiary calls withdraw() from receive() --");
  const attacker = await ethers.deployContract("ReentrantBeneficiary");
  await attacker.waitForDeployment();
  const attackerAddress = await attacker.getAddress();

  const campaign2 = await ethers.deployContract("Crowdfunding", [attackerAddress, eth(5)]);
  await campaign2.waitForDeployment();
  const campaign2Address = await campaign2.getAddress();
  await (await attacker.setCampaign(campaign2Address)).wait();

  await (await campaign2.connect(alice).contribute({ value: eth(5) })).wait();
  console.log(`  campaign2 raised          : ${fmt(await campaign2.totalRaised())}`);

  // withdraw() is onlyBeneficiary, so the call must come from the attacker
  // contract itself. Hardhat can impersonate it; on a real chain the attacker
  // would simply have added a function that forwards the call.
  const attackerSigner = await ethers.getImpersonatedSigner(attackerAddress);
  // Give the attacker gas money by setting its balance directly. Sending it a
  // normal transfer would run its receive() and spoil the experiment.
  await ethers.provider.send("hardhat_setBalance", [attackerAddress, "0xDE0B6B3A7640000"]);
  await (await campaign2.connect(attackerSigner).withdraw()).wait();

  check("re-entrant call was attempted", (await attacker.reentryAttempts()) === 1n);
  check("re-entrant withdrawal FAILED (defence holds)", (await attacker.reentrySucceeded()) === false);
  check("campaign2 paid out exactly once",
    (await ethers.provider.getBalance(campaign2Address)) === 0n);
  check("attacker holds only the single legitimate payout",
    (await attacker.amountReceived()) === eth(5), fmt(await attacker.amountReceived()));

  // -----------------------------------------------------------------------
  console.log("\n" + "=".repeat(74));
  console.log(`RESULT: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(74));
  if (failed > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
