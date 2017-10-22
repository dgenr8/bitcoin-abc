// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"

#include <deque>

/**
 * Compute the next required proof of work using the legacy Bitcoin difficulty
 * adjustement + Emergency Difficulty Adjustement (EDA).
 */
static uint32_t GetNextEDAWorkRequired(const CBlockIndex *pindexPrev,
                                       const CBlockHeader *pblock,
                                       const Consensus::Params &params) {
    // Only change once per difficulty adjustment interval
    uint32_t nHeight = pindexPrev->nHeight + 1;
    if (nHeight % params.DifficultyAdjustmentInterval() == 0) {
        // Go back by what we want to be 14 days worth of blocks
        assert(nHeight >= params.DifficultyAdjustmentInterval());
        uint32_t nHeightFirst = nHeight - params.DifficultyAdjustmentInterval();
        const CBlockIndex *pindexFirst = pindexPrev->GetAncestor(nHeightFirst);
        assert(pindexFirst);

        return CalculateNextWorkRequired(pindexPrev,
                                         pindexFirst->GetBlockTime(), params);
    }

    const uint32_t nProofOfWorkLimit =
        UintToArith256(params.powLimit).GetCompact();

    if (params.fPowAllowMinDifficultyBlocks) {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* 10 minutes then allow
        // mining of a min-difficulty block.
        if (pblock->GetBlockTime() >
            pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing) {
            return nProofOfWorkLimit;
        }

        // Return the last non-special-min-difficulty-rules-block
        const CBlockIndex *pindex = pindexPrev;
        while (pindex->pprev &&
               pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
               pindex->nBits == nProofOfWorkLimit) {
            pindex = pindex->pprev;
        }

        return pindex->nBits;
    }

    // We can't go bellow the minimum, so early bail.
    uint32_t nBits = pindexPrev->nBits;
    if (nBits == nProofOfWorkLimit) {
        return nProofOfWorkLimit;
    }

    // If producing the last 6 block took less than 12h, we keep the same
    // difficulty.
    const CBlockIndex *pindex6 = pindexPrev->GetAncestor(nHeight - 7);
    assert(pindex6);
    int64_t mtp6blocks =
        pindexPrev->GetMedianTimePast() - pindex6->GetMedianTimePast();
    if (mtp6blocks < 12 * 3600) {
        return nBits;
    }

    // If producing the last 6 block took more than 12h, increase the difficulty
    // target by 1/4 (which reduces the difficulty by 20%). This ensure the
    // chain do not get stuck in case we lose hashrate abruptly.
    arith_uint256 nPow;
    nPow.SetCompact(nBits);
    nPow += (nPow >> 2);

    // Make sure we do not go bellow allowed values.
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    if (nPow > bnPowLimit) nPow = bnPowLimit;

    return nPow.GetCompact();
}

uint32_t GetNextWorkRequired(const CBlockIndex *pindexPrev,
                             const CBlockHeader *pblock,
                             const Consensus::Params &params) {
    // Genesis block
    if (pindexPrev == nullptr) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting) {
        return pindexPrev->nBits;
    }

    return GetNextEDAWorkRequired(pindexPrev, pblock, params);
}

uint32_t CalculateNextWorkRequired(const CBlockIndex *pindexPrev,
                                   int64_t nFirstBlockTime,
                                   const Consensus::Params &params) {
    if (params.fPowNoRetargeting) {
        return pindexPrev->nBits;
    }

    // Limit adjustment step
    int64_t nActualTimespan = pindexPrev->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4) {
        nActualTimespan = params.nPowTargetTimespan / 4;
    }

    if (nActualTimespan > params.nPowTargetTimespan * 4) {
        nActualTimespan = params.nPowTargetTimespan * 4;
    }

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit) bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, uint32_t nBits,
                      const Consensus::Params &params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    return true;
}

static std::deque<const CBlockIndex*> BlocksInRange(
        const CBlockIndex *pindexFirst,
        const CBlockIndex *pindexLast)
{
  std::deque<const CBlockIndex*> blocks;
  for (const CBlockIndex* i = pindexLast; i != pindexFirst; i = i->pprev) {
    blocks.push_front(i);
  }
  return blocks;
}

/**
 * Compute the a target based on the work done between 2 blocks and the time
 * required to produce that work.
 */
static arith_uint256 ComputeTarget(const CBlockIndex *pindexFirst,
				                   const CBlockIndex *pindexLast)
{
  assert(pindexLast->nHeight > pindexFirst->nHeight);
  std::deque<const CBlockIndex*> blocks = BlocksInRange(pindexFirst, pindexLast);

  // last_target = bits_to_target(states[last].bits)
  arith_uint256 last_target;
  last_target.SetCompact(pindexLast->nBits);

  // timespan = 0
  // prior_timestamp = states[first].timestamp
  uint32_t timespan = 0;
  uint32_t prior_timestamp = pindexFirst->nTime;

  // for i in range(first + 1, last + 1):
  for (auto i = begin(blocks); i != end(blocks); ++i) {
    // target_i = bits_to_target(states[i].bits)
    arith_uint256 target_i;
    target_i.SetCompact((*i)->nBits);

    // Prevent negative time_i values
    //
    // timestamp = max(states[i].timestamp, prior_timestamp)
    // time_i = timestamp - prior_timestamp
    // prior_timestamp = timestamp
    uint32_t timestamp = std::max((*i)->nTime, prior_timestamp);
    uint32_t time_i = timestamp - prior_timestamp;
    prior_timestamp = timestamp;

    // Difficulty weight
    // adj_time_i = time_i * target_i // last_target # Difficulty weight
    uint32_t adj_time_i = time_i * (target_i / last_target).GetLow64();

    // Recency weight
    // timespan += adj_time_i * i # Recency weight
    timespan += adj_time_i * (std::distance(begin(blocks), i) + 1);
  }

  int block_count = blocks.size();
  // Normalize recency weight
  // timespan = timespan * 2 // (block_count + 1)
  timespan = timespan * 2 / (block_count + 1);

  // Standard retarget
  // target = last_target * timespan # Standard retarget
  // target //= 600 * block_count
  arith_uint256 target = last_target * timespan;
  target /= 600 * block_count;
  return target;
}

/**
 * Compute the next required proof of work using a weighted average of the
 * estimated hashrate per block.
 *
 * Additionally, weight most recent blocks more heavily using an arithmetic
 * sequence that drops to zero just before the earliest block in the window.
 */
uint32_t GetNextCashWorkRequired(const CBlockIndex *pindexPrev,
                                 const CBlockHeader *pblock,
                                 const Consensus::Params &params) {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev);

    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Compute the difficulty based on the full adjustment interval.
    const uint32_t nHeight = pindexPrev->nHeight;
    assert(nHeight >= params.DifficultyAdjustmentInterval());

    // Find the last block before the difficulty interval.
    uint32_t nHeightFirst = nHeight - 144;
    const CBlockIndex *pindexFirst = pindexPrev->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    // Compute the target based on time and work done during the interval.
    const arith_uint256 nextTarget = ComputeTarget(pindexFirst, pindexPrev);

    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    if (nextTarget > powLimit) {
        return powLimit.GetCompact();
    }

    return nextTarget.GetCompact();
}
