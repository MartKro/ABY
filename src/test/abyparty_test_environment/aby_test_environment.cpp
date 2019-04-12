#include "./aby_test_environment.h"
#include <ENCRYPTO_utils/crypto/crypto.h>

void ABYPartyTestParameters::reseed() {
    uint64_t next_seed = dist(seed_rng);
    client_rng.seed(next_seed);
    server_rng.seed(next_seed);
}

void ABYPartyTestParameters::SetUp() {
    slvl = get_sec_lvl(slvlbits);
    if(randomseed) {
        seed_rng.seed(std::time(NULL));
    } else {
        seed_rng.seed(seed);
    }
    client_party = new ABYParty(CLIENT, address, port, slvl, bitlen, nthreads, mt_alg, 4000000);
    pool.AddJob(std::bind(&ABYParty::ConnectAndBaseOTs, client_party));
    server_party = new ABYParty(SERVER, address, port, slvl, bitlen, nthreads, mt_alg, 4000000);
    pool.AddJob(std::bind(&ABYParty::ConnectAndBaseOTs, server_party));
    pool.WaitAll();
    reseed();
}

ABYPartyTestParameters::~ABYPartyTestParameters() {
    testparameters = NULL;
}

ABYPartyTestParameters* ABYPartyTestParameters::testparameters = new ABYPartyTestParameters();
