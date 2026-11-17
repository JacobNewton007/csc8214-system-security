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

  await (await campaign.connect(bob).contribute({ value: eth(2) })).wait();
  await expectRevert(
    "late contributions cannot be withdrawn either (latch is permanent)",
    campaign.connect(beneficiary).withdraw(),
    "AlreadyWithdrawn"
  );
  check(
    "the 2 ETH that arrived late is now stuck in the contract (see B.5)",
    (await ethers.provider.getBalance(await campaign.getAddress())) === eth(2)
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
