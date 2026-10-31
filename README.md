# TaskMarket Diamond (rev025) — Security Audit Findings

**Auditor:** kazuyaroz  
**Wallet:** 0x9b2a56b912659a24db94473526d2c67814a117Ac  
**Date:** 2026-10-31  
**Scope:** TaskMarket Diamond (Tempo mainnet, rev025), PGTR Forwarder, Solidity sources at github.com/daydreamsai/taskmarket-contracts

## Summary

Audited the TaskMarket diamond contract (14,428 lines of Solidity across 40+ files), focusing on fund safety, role integrity, and access control. The codebase demonstrates strong security engineering: conservative escrow accounting with solvency checks, reentrancy guards on all money-moving paths, forwarder-gated authentication, and extensive documentation of past fixes.

One finding identified: missing input validation on multi-winner bounty settlement shares.

## Finding: Missing Share Sum Validation in acceptSubmissions

**Severity:** Low  
**Location:** `evm/src/facets/AcceptanceFacet.sol`, `_acceptSubmissions()` (line 258)  
**Type:** Input validation / CWE-20

### Description

The `acceptSubmissions` function documentation states:

```solidity
///         Valid for Bounty and Benchmark modes. Shares MUST sum to 10000.
/// @param shares           Basis-point shares; MUST sum to 10000
```

However, the implementation does not enforce this constraint. The `_acceptSubmissions` function validates only:
- `shares.length == workers.length` (length match)
- `n >= 1` (at least one winner)

It does not verify that `sum(shares) <= 10000`. The shares are used directly:

```solidity
awards[i] = ITMPCore.Award({ 
    worker: workers[i], 
    amount: (reward * shares[i]) / 10000, 
    rank: uint16(i + 1) 
});
```

### Impact

If shares sum to more than 10000 (100%), the total awarded to workers exceeds the escrowed reward. For example, with a 10,000 USDC reward and shares [8000, 8000] (160%), workers receive 16,000 USDC total.

The overpayment is partially mitigated by the escrow conservation check in `LibEscrow.release()`, which reverts if `paidOut > released`. However, the check uses the task's booked liability (`reward + evaluatorStake` for Bounty/Benchmark), not the reward alone. If the task has a non-trivial evaluator stake, the excess worker payments are drawn from the evaluator's stake rather than being rejected. This means:

1. The evaluator stake (meant to be returned to the requester or forfeited to the protocol on evaluator timeout) is silently consumed by overpaid workers.
2. The requester who set incorrect shares is not warned; the transaction succeeds as long as the evaluator stake covers the excess.

Conversely, if shares sum to less than 10000, the remainder is correctly refunded via `_refundSplitRemainder()`, so under-payment is handled gracefully.

### Suggested Fix

Add a share sum validation loop in `_acceptSubmissions`:

```solidity
uint256 shareSum;
for (uint256 i; i < n; ++i) {
    shareSum += shares[i];
}
if (shareSum != 10000) revert ITMPCore.InvalidShareSum();
```

Or, if partial shares are intentionally allowed (with remainder refund), add an upper bound:

```solidity
if (shareSum > 10000) revert ITMPCore.ShareSumExceeds100Percent();
```

## Areas Audited (No Findings)

### Escrow Accounting (LibEscrow.sol)
- `owed()` correctly derives liability from task state
- `book()` and `release()` enforce conservation: `paidOut <= released`
- `requireSolvent()` checks `balance >= totalLiabilities` after every operation
- Terminal statuses (Accepted, Expired, Cancelled) correctly zero out liability
- Backfill for pre-rev026 tasks is idempotent and safe

### Authentication (LibGuards.sol, TaskMarketForwarderV2.sol)
- All state-changing functions require `_requireForwarder()` (trusted forwarder check)
- `_effectiveSender()` resolves the authenticated actor via `pgtrSender()`
- `_requireRequester()` centralizes requester authorization
- Forwarder uses `nonReentrant`, receipt nonces prevent replay, calldata length checked
- `_requireReportedPayment()` verifies forwarded payment amounts match expectations

### Settlement Paths (SettlementFacet.sol)
- `refundExpired`: permissionless, checks Expired status to prevent double-refund (documented past fix), blocks on active submissions and pending deliveries
- `cancelTask`: requester-only, Open status only, blocks on bids and active submissions
- `forfeitAndReopen`: CLAIM-only, Claimed status only, no deliverable, expired only
- `releaseClaim`: worker-only, before expiry, deliverable not set, release allowed by terms
- `requesterTimeout`: permissionless, BOUNTY/BENCHMARK only, decision window lapsed, active submissions required
- `_releasePenalty`: division-by-zero guarded by caller's `block.timestamp < expiry` check

### Acceptance (AcceptanceFacet.sol)
- Single and multi-winner paths both call `LibEscrow.release()` after transfers
- Fee computation is consistent between accumulation and transfer passes
- Zero-amount awards rejected
- Self-awards emit events (transparency, not prevention)
- `_refundSplitRemainder` handles under-100% share sums correctly

### Worker Submission (WorkerFacet.sol)
- `submitWork` routes by mode: BOUNTY/BENCHMARK push to submission hashes, CLAIM/PITCH/AUCTION set deliverable
- `_recordDelivery` prevents duplicate deliverables unless revision is open
- Revision window logic in LibReview correctly tracks deliveredAt and revisionDueAt

### Forwarder (TaskMarketForwarderV2.sol)
- Immutable, non-upgradeable
- Authorized relayer only
- Receipt hash includes chainid, sender, amount, nonce, validBefore, target, selector
- Context cleared after call, protected by nonReentrant
- Bubbles up revert reasons verbatim

## Methodology

1. Repository cloned and full source reviewed (14,428 lines, 40+ Solidity files)
2. Money-moving entrypoints traced end-to-end: createTask -> claim -> submitWork -> acceptSubmission/rejectSubmission -> settlement
3. Escrow accounting verified: book/release/solvency checks at every payout site
4. Authentication verified: forwarder gates, effective sender resolution, requester/worker role checks
5. Edge cases analyzed: expiry boundaries, reentrancy, double-refund, share overflow, division by zero
6. Cross-referenced with documentation comments for stated invariants vs implemented checks

## Reproduction

The share sum issue is reproducible by:
1. Create a Bounty task with reward R and evaluator stake E
2. Have workers submit
3. Call `acceptSubmissions` with shares summing to > 10000 where `R * (shareSum/10000) - R < E`
4. Observe: transaction succeeds, workers overpaid, evaluator stake consumed

No proof-of-concept contract is included as this is a code review finding, not an exploitable on-chain vulnerability requiring demonstration.
