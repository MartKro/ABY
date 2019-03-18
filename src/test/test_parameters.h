#ifndef __TEST_PARAMETERS_H__
#define __TEST_PARAMETERS_H__

#include <random>

#include <boost/test/unit_test.hpp>

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/parse_options.h>

#include "../abycore/aby/abyparty.h"
#include "../abycore/circuit/circuit.h"
#include "../abycore/sharing/sharing.h"


typedef std::mt19937_64 MyRNG;

struct TestParameters {
    TestParameters() : address("127.0.0.1"), port(7766), slvl(get_sec_lvl(128)), nvals(65), bitlen(32), nthreads(1), 
            nelements(1024), mt_alg(MT_OT), num_test_runs(2), seed(0xC0FFEE23DEADBEEF) {
        client_party = new ABYParty(CLIENT, TestParameters::address, port, slvl, bitlen, nthreads, mt_alg);
        server_party = new ABYParty(SERVER, TestParameters::address, port, slvl, bitlen, nthreads, mt_alg);
        client_rng.seed(seed);
        server_rng.seed(seed);
    }

    ~TestParameters() {
        //does stay on an infinitive loop currently
        //delete client_party;
        //delete server_party;
    }

    //user dependend parameters
    const std::string& address;
    uint16_t port;
    seclvl slvl;
    uint32_t nvals;
    uint32_t bitlen;
    uint32_t nthreads;
    uint32_t nelements;
    e_mt_gen_alg mt_alg;
    uint32_t num_test_runs;
    uint64_t seed;

    std::uniform_int_distribution<uint64_t> client_dist;
    std::uniform_int_distribution<uint64_t> server_dist;

    //dependent parameters
    ABYParty* client_party;
    ABYParty* server_party;
    MyRNG client_rng;
    MyRNG server_rng;
};

#endif //__TEST_PARAMETERS_H__
