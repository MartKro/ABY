#ifndef __ABY_TEST_ENVIRONMENT_H__
#define __ABY_TEST_ENVIRONMENT_H__

#include <random>

#include <gtest/gtest.h>

#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/circuit.h"

#include "./threadpool.h"


typedef std::mt19937_64 MyRNG;

static const std::string& local_address = "127.0.0.1";

class ABYPartyTestParameters : public testing::Environment {
    private:
        ABYPartyTestParameters() : address(local_address), port(7766), slvlbits(128),
                bitlen(32), nthreads(1), mt_alg(MT_OT), num_test_runs(25),
                seed(0xC0FFEE23DEADBEEF), randomseed(false) {
            
        }

    public:
        static ABYPartyTestParameters* GetABYPartyTestParameters() {
            return ABYPartyTestParameters::testparameters;
        }

        void SetUp() override;

        inline void TearDown() override {
            //TODO blocks currently, therefore delete is disabled and we leak memory currently
            //delete client_party;
            //delete server_party;
            //end TODO
        }

        void reseed();

        ~ABYPartyTestParameters();

        //user dependend non-changing parameters during the tests
        const std::string& address;
        uint16_t port;
        uint32_t slvlbits;
        uint32_t bitlen;
        uint32_t nthreads;
        e_mt_gen_alg mt_alg;
        uint32_t num_test_runs;
        uint64_t seed;
        bool randomseed;

        seclvl slvl;
        std::uniform_int_distribution<uint64_t> dist;

        //dependent parameters which may change during the tests
        ABYParty* client_party;
        ABYParty* server_party;
        MyRNG client_rng;
        MyRNG server_rng;
        MyRNG seed_rng;

        nbsdx::concurrent::ThreadPool<2> pool;

        //Always use this for every google test call like EXPECT_EQ since operations run in a thread
        std::mutex test_mutex;

    private:
        static ABYPartyTestParameters* testparameters;
};

#endif //__ABY_TEST_ENVIRONMENT_H__
