// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"

#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_CSV = 0, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_TESTDUMMY = 28,
    MAX_VERSION_BITS_DEPLOYMENTS = 29
};

/**
 * Struct for each individual consensus rule change using BIP135.
 */
struct ForkDeployment
{
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    /** Window size (in blocks) for generalized versionbits signal tallying */
    int windowsize;
    /** Threshold (in blocks / window) for generalized versionbits lock-in */
    int threshold;
    /** Minimum number of blocks to remain in locked-in state */
    int minlockedblocks;
    /** Minimum duration (in seconds based on MTP) to remain in locked-in state */
    int64_t minlockedtime;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which UAHF kicks in */
    int uahfHeight;
    /** Block height at which the new DAA becomes active */
    int daaHeight;
    /** Unix time used for MTP activation of May 15 2018, hardfork */
    int monolithActivationTime;
    /** Unix time used for MTP activation of Nov 15 2018, hardfork */
    int magneticAnomalyActivationTime;
    /** Defined BIP135 deployments. */
    std::map<DeploymentPos, ForkDeployment> vDeployments;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const {
        return nPowTargetTimespan / nPowTargetSpacing;
    }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
