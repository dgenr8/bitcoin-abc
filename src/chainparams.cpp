// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <cassert>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation transaction
 * cannot be spent since it did not originally exist in the database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
 * hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893,
 * vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase
 * 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

void CChainParams::UpdateBIP9Parameters(Consensus::DeploymentPos d,
                                        int64_t nStartTime, int64_t nTimeout) {
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S(
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 388381;
        // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 363725;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].name = "csv";
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].gbt_force = true;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800LL; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800LL; // May 1st, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].windowsize = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].threshold = 1916; // 95% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].minlockedblocks = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].minlockedtime = 0;

        // testing bit
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].name = "testdummy";
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].gbt_force = false;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601LL; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999LL; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].windowsize = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1916; // 95% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].minlockedblocks = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].minlockedtime = 0;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(
            "000000000000000000000000000000000000000000a0f3064330647e2f6c4828");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S(
            "000000000000000000e45ad2fbcc5ff3e85f0868dd8f00ad4e92dffabe28f8d2");

        // August 1, 2017 hard fork
        consensus.uahfHeight = 478558;

        // November 13, 2017 hard fork
        consensus.daaHeight = 504031;

        // May 15, 2018 hard fork
        consensus.monolithActivationTime = 1526400000;

        // Nov 15, 2018 hard fork
        consensus.magneticAnomalyActivationTime = 1542300000;

        /**
         * The message start string is designed to be unlikely to occur in
         * normal data. The characters are rarely used upper ASCII, not valid as
         * UTF-8, and produce a large 32-bit integer with any alignment.
         */
        diskMagic[0] = 0xf9;
        diskMagic[1] = 0xbe;
        diskMagic[2] = 0xb4;
        diskMagic[3] = 0xd9;
        netMagic[0] = 0xe3;
        netMagic[1] = 0xe1;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xe8;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1,
                                     50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1"
                        "b60a8ce26f"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));

        // Note that of those with the service bits flag, most only support a
        // subset of possible options.
        // Bitcoin ABC seeder
        vSeeds.push_back(
            CDNSSeedData("bitcoinabc.org", "seed.bitcoinabc.org", true));
        // bitcoinforks seeders
        vSeeds.push_back(CDNSSeedData("bitcoinforks.org",
                                      "seed-abc.bitcoinforks.org", true));
        // BU backed seeder
        vSeeds.push_back(CDNSSeedData("bitcoinunlimited.info",
                                      "btccash-seeder.bitcoinunlimited.info",
                                      true));
        // Bitprim
        vSeeds.push_back(CDNSSeedData("bitprim.org", "seed.bitprim.org", true));
        // Amaury SÉCHET
        vSeeds.push_back(
            CDNSSeedData("deadalnix.me", "seed.deadalnix.me", true));
        // criptolayer.net
        vSeeds.push_back(
            CDNSSeedData("criptolayer.net", "seeder.criptolayer.net", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 5);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        cashaddrPrefix = "bitcoincash";

        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            .mapCheckpoints = {
                {11111, uint256S("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee"
                                 "92559f542fdb26e7c1d")},
                {33333, uint256S("000000002dd5588a74784eaa7ab0507a18ad16a236e7b"
                                 "1ce69f00d7ddfb5d0a6")},
                {74000, uint256S("0000000000573993a3c9e41ce34471c079dcf5f52a0e8"
                                 "24a81e7f953b8661a20")},
                {105000, uint256S("00000000000291ce28027faea320c8d2b054b2e0fe44"
                                  "a773f3eefb151d6bdc97")},
                {134444, uint256S("00000000000005b12ffd4cd315cd34ffd4a594f430ac"
                                  "814c91184a0d42d2b0fe")},
                {168000, uint256S("000000000000099e61ea72015e79632f216fe6cb33d7"
                                  "899acb35b75c8303b763")},
                {193000, uint256S("000000000000059f452a5f7340de6682a977387c1701"
                                  "0ff6e6c3bd83ca8b1317")},
                {210000, uint256S("000000000000048b95347e83192f69cf0366076336c6"
                                  "39f9b7228e9ba171342e")},
                {216116, uint256S("00000000000001b4f4b433e81ee46494af945cf96014"
                                  "816a4e2370f11b23df4e")},
                {225430, uint256S("00000000000001c108384350f74090433e7fcf79a606"
                                  "b8e797f065b130575932")},
                {250000, uint256S("000000000000003887df1f29024b06fc2200b55f8af8"
                                  "f35453d7be294df2d214")},
                {279000, uint256S("0000000000000001ae8c72a0b0c301f67e3afca10e81"
                                  "9efa9041e458e9bd7e40")},
                {295000, uint256S("00000000000000004d9b4ef50f0f9d686fd69db2e03a"
                                  "f35a100370c64632a983")},
                // UAHF fork block.
                {478558, uint256S("0000000000000000011865af4122fe3b144e2cbeea86"
                                  "142e8ff2fb4107352d43")},
                // Nov, 13 DAA activation block.
                {504031, uint256S("0000000000000000011ebf65b60d0a3de80b8175be70"
                                  "9d653b4c1a1beeb6ab9c")},
                // Monolith activation.
                {530359, uint256S("0000000000000000011ada8bd08f46074f44a8f15539"
                                  "6f43e38acf9501c49103")},
            }};

        // Data as of block
        // 000000000000000001d2ce557406b017a928be25ee98906397d339c3f68eec5d
        // (height 523992).
        chainTxData = ChainTxData{
            // UNIX timestamp of last known number of transactions.
            1522608016,
            // Total number of transactions between genesis and that timestamp
            // (the tx=... number in the SetBestChain debug.log lines)
            248589038,
            // Estimated number of transactions per second after that timestamp.
            3.2};
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S(
            "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP65Height = 581885;
        // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BIP66Height = 330776;
        consensus.powLimit = uint256S(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(
            "00000000000000000000000000000000000000000000002a650f6ff7649485da");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S(
            "0000000000327972b8470c11755adf8f4319796bafae01f5a6650490b98a17db");

        // August 1, 2017 hard fork
        consensus.uahfHeight = 1155875;

        // November 13, 2017 hard fork
        consensus.daaHeight = 1188697;

        // May 15, 2018 hard fork
        consensus.monolithActivationTime = 1526400000;

        // Nov 15, 2018 hard fork
        consensus.magneticAnomalyActivationTime = 1542300000;

        diskMagic[0] = 0x0b;
        diskMagic[1] = 0x11;
        diskMagic[2] = 0x09;
        diskMagic[3] = 0x07;
        netMagic[0] = 0xf4;
        netMagic[1] = 0xe5;
        netMagic[2] = 0xf3;
        netMagic[3] = 0xf4;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].name = "csv";
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].gbt_force = true;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400LL; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800LL; // May 1st, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].windowsize = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].threshold = 1916; // 95% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].minlockedblocks = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].minlockedtime = 0;

        // testing bit
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].name = "testdummy";
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].gbt_force = false;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601LL; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999LL; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].windowsize = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 1916; // 95% of 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].minlockedblocks = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].minlockedtime = 0;

        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;

        genesis =
            CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526"
                        "f8d77f4943"));
        assert(genesis.hashMerkleRoot ==
               uint256S("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b"
                        "7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // Bitcoin ABC seeder
        vSeeds.push_back(CDNSSeedData("bitcoinabc.org",
                                      "testnet-seed.bitcoinabc.org", true));
        // bitcoinforks seeders
        vSeeds.push_back(CDNSSeedData(
            "bitcoinforks.org", "testnet-seed-abc.bitcoinforks.org", true));
        // Bitprim
        vSeeds.push_back(
            CDNSSeedData("bitprim.org", "testnet-seed.bitprim.org", true));
        // Amaury SÉCHET
        vSeeds.push_back(
            CDNSSeedData("deadalnix.me", "testnet-seed.deadalnix.me", true));
        // criptolayer.net
        vSeeds.push_back(CDNSSeedData("criptolayer.net",
                                      "testnet-seeder.criptolayer.net", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchtest";
        vFixedSeeds = std::vector<SeedSpec6>(
            pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            .mapCheckpoints = {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345"
                               "d31b1bcebf76acb70")},
                // UAHF fork block.
                {1155875, uint256S("00000000f17c850672894b9a75b63a1e72830bbd5f4"
                                   "c8889b5c1a80e7faef138")},
                // Nov, 13. DAA activation block.
                {1188697, uint256S("0000000000170ed0918077bde7b4d36cc4c91be69fa"
                                   "09211f748240dabe047fb")},
            }};

        // Data as of block
        // 000000000005b07ecf85563034d13efd81c1a29e47e22b20f4fc6919d5b09cd6
        // (height 1223263)
        chainTxData = ChainTxData{1522608381, 15052068, 0.15};
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        // BIP34 has not activated on regtest (far in the future so block v1 are
        // not rejected in tests)
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].name = "csv";
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].gbt_force = true;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999LL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].windowsize = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].threshold = 108; // 75% of 144
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].minlockedblocks = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].minlockedtime = 0;

        // BIP135 functional tests rely on deterministic block times
        int64_t MOCKTIME = 1388534400 + (201 * 10 * 60); // Jan 1, 2014

        Consensus::DeploymentPos bip135test1 = static_cast<Consensus::DeploymentPos>(1);
        consensus.vDeployments[bip135test1].name = "bip135test1";
        consensus.vDeployments[bip135test1].gbt_force = true;
        consensus.vDeployments[bip135test1].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test1].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test1].windowsize = 144;
        consensus.vDeployments[bip135test1].threshold = 108;
        consensus.vDeployments[bip135test1].minlockedblocks = 0;
        consensus.vDeployments[bip135test1].minlockedtime = 0;

        Consensus::DeploymentPos bip135test2 = static_cast<Consensus::DeploymentPos>(2);
        consensus.vDeployments[bip135test2].name = "bip135test2";
        consensus.vDeployments[bip135test2].gbt_force = true;
        consensus.vDeployments[bip135test2].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test2].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test2].windowsize = 100;
        consensus.vDeployments[bip135test2].threshold = 1;
        consensus.vDeployments[bip135test2].minlockedblocks = 0;
        consensus.vDeployments[bip135test2].minlockedtime = 0;

        Consensus::DeploymentPos bip135test3 = static_cast<Consensus::DeploymentPos>(3);
        consensus.vDeployments[bip135test3].name = "bip135test3";
        consensus.vDeployments[bip135test3].gbt_force = true;
        consensus.vDeployments[bip135test3].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test3].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test3].windowsize = 100;
        consensus.vDeployments[bip135test3].threshold = 10;
        consensus.vDeployments[bip135test3].minlockedblocks = 0;
        consensus.vDeployments[bip135test3].minlockedtime = 0;

        Consensus::DeploymentPos bip135test4 = static_cast<Consensus::DeploymentPos>(4);
        consensus.vDeployments[bip135test4].name = "bip135test4";
        consensus.vDeployments[bip135test4].gbt_force = true;
        consensus.vDeployments[bip135test4].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test4].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test4].windowsize = 100;
        consensus.vDeployments[bip135test4].threshold = 75;
        consensus.vDeployments[bip135test4].minlockedblocks = 0;
        consensus.vDeployments[bip135test4].minlockedtime = 0;

        Consensus::DeploymentPos bip135test5 = static_cast<Consensus::DeploymentPos>(5);
        consensus.vDeployments[bip135test5].name = "bip135test5";
        consensus.vDeployments[bip135test5].gbt_force = true;
        consensus.vDeployments[bip135test5].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test5].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test5].windowsize = 100;
        consensus.vDeployments[bip135test5].threshold = 95;
        consensus.vDeployments[bip135test5].minlockedblocks = 0;
        consensus.vDeployments[bip135test5].minlockedtime = 0;

        Consensus::DeploymentPos bip135test6 = static_cast<Consensus::DeploymentPos>(6);
        consensus.vDeployments[bip135test6].name = "bip135test6";
        consensus.vDeployments[bip135test6].gbt_force = true;
        consensus.vDeployments[bip135test6].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test6].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test6].windowsize = 100;
        consensus.vDeployments[bip135test6].threshold = 99;
        consensus.vDeployments[bip135test6].minlockedblocks = 0;
        consensus.vDeployments[bip135test6].minlockedtime = 0;

        Consensus::DeploymentPos bip135test7 = static_cast<Consensus::DeploymentPos>(7);
        consensus.vDeployments[bip135test7].name = "bip135test7";
        consensus.vDeployments[bip135test7].gbt_force = true;
        consensus.vDeployments[bip135test7].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test7].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test7].windowsize = 100;
        consensus.vDeployments[bip135test7].threshold = 100;
        consensus.vDeployments[bip135test7].minlockedblocks = 0;
        consensus.vDeployments[bip135test7].minlockedtime = 0;

        Consensus::DeploymentPos bip135test8 = static_cast<Consensus::DeploymentPos>(8);
        consensus.vDeployments[bip135test8].name = "bip135test8";
        consensus.vDeployments[bip135test8].gbt_force = true;
        consensus.vDeployments[bip135test8].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test8].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test8].windowsize = 10;
        consensus.vDeployments[bip135test8].threshold = 9;
        consensus.vDeployments[bip135test8].minlockedblocks = 1;
        consensus.vDeployments[bip135test8].minlockedtime = 0;

        Consensus::DeploymentPos bip135test9 = static_cast<Consensus::DeploymentPos>(9);
        consensus.vDeployments[bip135test9].name = "bip135test9";
        consensus.vDeployments[bip135test9].gbt_force = true;
        consensus.vDeployments[bip135test9].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test9].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test9].windowsize = 10;
        consensus.vDeployments[bip135test9].threshold = 9;
        consensus.vDeployments[bip135test9].minlockedblocks = 5;
        consensus.vDeployments[bip135test9].minlockedtime = 0;

        Consensus::DeploymentPos bip135test10 = static_cast<Consensus::DeploymentPos>(10);
        consensus.vDeployments[bip135test10].name = "bip135test10";
        consensus.vDeployments[bip135test10].gbt_force = true;
        consensus.vDeployments[bip135test10].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test10].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test10].windowsize = 10;
        consensus.vDeployments[bip135test10].threshold = 9;
        consensus.vDeployments[bip135test10].minlockedblocks = 10;
        consensus.vDeployments[bip135test10].minlockedtime = 0;

        Consensus::DeploymentPos bip135test11 = static_cast<Consensus::DeploymentPos>(11);
        consensus.vDeployments[bip135test11].name = "bip135test11";
        consensus.vDeployments[bip135test11].gbt_force = true;
        consensus.vDeployments[bip135test11].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test11].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test11].windowsize = 10;
        consensus.vDeployments[bip135test11].threshold = 9;
        consensus.vDeployments[bip135test11].minlockedblocks = 11;
        consensus.vDeployments[bip135test11].minlockedtime = 0;

        Consensus::DeploymentPos bip135test12 = static_cast<Consensus::DeploymentPos>(12);
        consensus.vDeployments[bip135test12].name = "bip135test12";
        consensus.vDeployments[bip135test12].gbt_force = true;
        consensus.vDeployments[bip135test12].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test12].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test12].windowsize = 10;
        consensus.vDeployments[bip135test12].threshold = 9;
        consensus.vDeployments[bip135test12].minlockedblocks = 0;
        consensus.vDeployments[bip135test12].minlockedtime = 0;

        Consensus::DeploymentPos bip135test13 = static_cast<Consensus::DeploymentPos>(13);
        consensus.vDeployments[bip135test13].name = "bip135test13";
        consensus.vDeployments[bip135test13].gbt_force = true;
        consensus.vDeployments[bip135test13].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test13].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test13].windowsize = 10;
        consensus.vDeployments[bip135test13].threshold = 9;
        consensus.vDeployments[bip135test13].minlockedblocks = 0;
        consensus.vDeployments[bip135test13].minlockedtime = 5;

        Consensus::DeploymentPos bip135test14 = static_cast<Consensus::DeploymentPos>(14);
        consensus.vDeployments[bip135test14].name = "bip135test14";
        consensus.vDeployments[bip135test14].gbt_force = true;
        consensus.vDeployments[bip135test14].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test14].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test14].windowsize = 10;
        consensus.vDeployments[bip135test14].threshold = 9;
        consensus.vDeployments[bip135test14].minlockedblocks = 0;
        consensus.vDeployments[bip135test14].minlockedtime = 9;

        Consensus::DeploymentPos bip135test15 = static_cast<Consensus::DeploymentPos>(15);
        consensus.vDeployments[bip135test15].name = "bip135test15";
        consensus.vDeployments[bip135test15].gbt_force = true;
        consensus.vDeployments[bip135test15].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test15].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test15].windowsize = 10;
        consensus.vDeployments[bip135test15].threshold = 9;
        consensus.vDeployments[bip135test15].minlockedblocks = 0;
        consensus.vDeployments[bip135test15].minlockedtime = 10;

        Consensus::DeploymentPos bip135test16 = static_cast<Consensus::DeploymentPos>(16);
        consensus.vDeployments[bip135test16].name = "bip135test16";
        consensus.vDeployments[bip135test16].gbt_force = true;
        consensus.vDeployments[bip135test16].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test16].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test16].windowsize = 10;
        consensus.vDeployments[bip135test16].threshold = 9;
        consensus.vDeployments[bip135test16].minlockedblocks = 0;
        consensus.vDeployments[bip135test16].minlockedtime = 11;

        Consensus::DeploymentPos bip135test17 = static_cast<Consensus::DeploymentPos>(17);
        consensus.vDeployments[bip135test17].name = "bip135test17";
        consensus.vDeployments[bip135test17].gbt_force = true;
        consensus.vDeployments[bip135test17].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test17].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test17].windowsize = 10;
        consensus.vDeployments[bip135test17].threshold = 9;
        consensus.vDeployments[bip135test17].minlockedblocks = 0;
        consensus.vDeployments[bip135test17].minlockedtime = 15;

        Consensus::DeploymentPos bip135test18 = static_cast<Consensus::DeploymentPos>(18);
        consensus.vDeployments[bip135test18].name = "bip135test18";
        consensus.vDeployments[bip135test18].gbt_force = true;
        consensus.vDeployments[bip135test18].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test18].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test18].windowsize = 10;
        consensus.vDeployments[bip135test18].threshold = 9;
        consensus.vDeployments[bip135test18].minlockedblocks = 10;
        consensus.vDeployments[bip135test18].minlockedtime = 10;

        Consensus::DeploymentPos bip135test19 = static_cast<Consensus::DeploymentPos>(19);
        consensus.vDeployments[bip135test19].name = "bip135test19";
        consensus.vDeployments[bip135test19].gbt_force = true;
        consensus.vDeployments[bip135test19].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test19].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test19].windowsize = 10;
        consensus.vDeployments[bip135test19].threshold = 9;
        consensus.vDeployments[bip135test19].minlockedblocks = 10;
        consensus.vDeployments[bip135test19].minlockedtime = 19;

        Consensus::DeploymentPos bip135test20 = static_cast<Consensus::DeploymentPos>(20);
        consensus.vDeployments[bip135test20].name = "bip135test20";
        consensus.vDeployments[bip135test20].gbt_force = true;
        consensus.vDeployments[bip135test20].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test20].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test20].windowsize = 10;
        consensus.vDeployments[bip135test20].threshold = 9;
        consensus.vDeployments[bip135test20].minlockedblocks = 10;
        consensus.vDeployments[bip135test20].minlockedtime = 20;

        Consensus::DeploymentPos bip135test21 = static_cast<Consensus::DeploymentPos>(21);
        consensus.vDeployments[bip135test21].name = "bip135test21";
        consensus.vDeployments[bip135test21].gbt_force = true;
        consensus.vDeployments[bip135test21].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test21].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test21].windowsize = 10;
        consensus.vDeployments[bip135test21].threshold = 9;
        consensus.vDeployments[bip135test21].minlockedblocks = 20;
        consensus.vDeployments[bip135test21].minlockedtime = 21;

        Consensus::DeploymentPos bip135test22 = static_cast<Consensus::DeploymentPos>(22);
        consensus.vDeployments[bip135test22].name = "bip135test22";
        consensus.vDeployments[bip135test22].gbt_force = true;
        consensus.vDeployments[bip135test22].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test22].nTimeout = 999999999999LL;
        consensus.vDeployments[bip135test22].windowsize = 10;
        consensus.vDeployments[bip135test22].threshold = 9;
        consensus.vDeployments[bip135test22].minlockedblocks = 21;
        consensus.vDeployments[bip135test22].minlockedtime = 20;

        Consensus::DeploymentPos bip135test23 = static_cast<Consensus::DeploymentPos>(23);
        consensus.vDeployments[bip135test23].name = "bip135test23";
        consensus.vDeployments[bip135test23].gbt_force = true;
        consensus.vDeployments[bip135test23].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test23].nTimeout = MOCKTIME + 30 + 50;
        consensus.vDeployments[bip135test23].windowsize = 10;
        consensus.vDeployments[bip135test23].threshold = 9;
        consensus.vDeployments[bip135test23].minlockedblocks = 5;
        consensus.vDeployments[bip135test23].minlockedtime = 0;

        Consensus::DeploymentPos bip135test24 = static_cast<Consensus::DeploymentPos>(24);
        consensus.vDeployments[bip135test24].name = "bip135test24";
        consensus.vDeployments[bip135test24].gbt_force = true;
        consensus.vDeployments[bip135test24].nStartTime = MOCKTIME + 30;
        consensus.vDeployments[bip135test24].nTimeout = MOCKTIME + 30 + 50;
        consensus.vDeployments[bip135test24].windowsize = 10;
        consensus.vDeployments[bip135test24].threshold = 8;
        consensus.vDeployments[bip135test24].minlockedblocks = 5;
        consensus.vDeployments[bip135test24].minlockedtime = 0;

        // testing bit
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].name = "testdummy";
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].gbt_force = false;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999LL;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].windowsize = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].threshold = 108; // 75% of 144
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].minlockedblocks = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].minlockedtime = 0;

        // UAHF is always enabled on regtest.
        consensus.uahfHeight = 0;

        // November 13, 2017 hard fork is always on on regtest.
        consensus.daaHeight = 0;

        // May 15, 2018 hard fork.
        consensus.monolithActivationTime = 1526400000;

        // Nov 15, 2018 hard fork
        consensus.magneticAnomalyActivationTime = 1542300000;

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b"
                        "1a11466e2206"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));

        //!< Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //!< Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {.mapCheckpoints = {
                              {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5"
                                           "beb436012afca590b1a11466e2206")},
                          }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    }

    if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    }

    if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime,
                          int64_t nTimeout) {
    globalChainParams->UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
