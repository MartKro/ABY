#define BOOST_TEST_MODULE aby_operations_test

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <thread>
#include <future>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <ENCRYPTO_utils/typedefs.h>
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/timer.h>
#include <ENCRYPTO_utils/parse_options.h>

#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/circuit.h"
#include "../../abycore/circuit/share.h"
#include "../../abycore/sharing/sharing.h"

#include "../test_parameters.h"

static const uint32_t TTSIZE = 16;
static const uint32_t TRUTH_TABLE[TTSIZE][4]={{0,0,0,0}, {1,0,0,0}, {0,1,0,0}, {1,1,0,0},
		{0,0,1,0}, {1,0,1,0}, {0,1,1,0}, {1,1,1,0},
		{0,0,0,1}, {1,0,0,1}, {0,1,0,1}, {1,1,0,1},
		{0,0,1,1}, {1,0,1,1}, {0,1,1,1}, {1,1,1,1},
};

std::mutex boost_test_mutex;

BOOST_FIXTURE_TEST_SUITE(vector_operation_tests, TestParameters)

void test_vector_ops(uint32_t operation, ABYParty* party, uint32_t bitlen, uint32_t nvals, uint32_t num_test_runs,
		e_role role, std::uniform_int_distribution<uint64_t> dist, MyRNG rng) {
	
	uint32_t *avec, *bvec, *cvec, *verifyvec, tmpbitlen, tmpnvals, sc, op, xbit, ybit;
	uint8_t *sa, *sb;
	uint32_t nvals_orig = nvals;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	share **shrres_vec;
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;

	sa = (uint8_t*) malloc(std::max(nvals, bitlen));
	sb = (uint8_t*) malloc(std::max(nvals, bitlen));

	avec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	bvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	cvec = nullptr;

	verifyvec = (uint32_t*) malloc(nvals * sizeof(uint32_t));
	for (uint32_t r = 0; r < num_test_runs; r++) {
		if(m_tAllOps[operation].op == OP_UNIV && nvals_orig > 32) {
			nvals = 32; //max nvals for universal gates
		}
		else {
			nvals = nvals_orig;
		}

		Circuit* circ = sharings[m_tAllOps[operation].sharing]->GetCircuitBuildRoutine();

		for (uint32_t j = 0; j < nvals; j++) {
			avec[j] = (uint32_t) dist(rng) % ((uint64_t) 1<<bitlen);;
			bvec[j] = (uint32_t) dist(rng) % ((uint64_t) 1<<bitlen);;
		}
		shra = circ->PutSIMDINGate(nvals, avec, bitlen, SERVER);
		shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);

		/*shra = circ->PutSIMDINGate(ceil_divide(nvals,2), avec, bitlen, SERVER);
		shrb = circ->PutSIMDINGate(nvals/2, avec+ceil_divide(nvals,2), bitlen, SERVER);

		//share* tmp = create_new_share(nvals, circ, circ->GetCircuitType());
		share* tmp;
		if(circ->GetCircuitType() == C_BOOLEAN) {
			tmp = new boolshare(2, circ);
			cout << "Boolean, max share len = " << tmp->max_size() << endl;
		}
		else {
			tmp = new arithshare(2, circ);
			cout << "Arithmetic" << endl;
		}

			for(uint32_t j = 0; j < bitlen; j++) {
			tmp->set_wire(0, shra->get_wire(j));
			tmp->set_wire(1, shrb->get_wire(j));

			shra->set_wire(j, circ->PutCombinerGate(tmp)->get_wire(0));

		}

		shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);*/

		switch (m_tAllOps[operation].op) {
			case OP_IO:
				shrres = shra;
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j];
				break;
			case OP_ADD:
				shrres = circ->PutADDGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] + bvec[j];
				break;
			case OP_SUB:
				shrres = circ->PutSUBGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] - bvec[j];
				break;
			case OP_MUL:
				shrres = circ->PutMULGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] * bvec[j];
				break;
			case OP_XOR:
				shrres = circ->PutXORGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] ^ bvec[j];
				break;
			case OP_AND:
				shrres = circ->PutANDGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] & bvec[j];
				break;
			case OP_CMP:
				shrres = circ->PutGTGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] > bvec[j];
				break;
			case OP_EQ:
				shrres = circ->PutEQGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] == bvec[j];
				break;
			case OP_MUX:
				for(uint32_t j = 0; j < nvals; j++) {
					 sa[j] = (uint8_t) (dist(rng) & 0x01);
					 sb[j] = (uint8_t) (dist(rng) & 0x01);
				}
				shrsel = circ->PutXORGate(circ->PutSIMDINGate(nvals, sa, 1, SERVER), circ->PutSIMDINGate(nvals, sb, 1, CLIENT));
				shrres = circ->PutMUXGate(shra, shrb, shrsel);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? bvec[j] : avec[j];
				break;
			case OP_X:
				for(uint32_t j = 0; j < nvals; j++) {
					sa[j] = (uint8_t) (dist(rng) & 0x01);
					sb[j] = (uint8_t) (dist(rng) & 0x01);
				}
				shrsel = circ->PutXORGate(circ->PutSIMDINGate(nvals, sa, 1, SERVER), circ->PutSIMDINGate(nvals, sb, 1, CLIENT));
				shrres_vec = circ->PutCondSwapGate(shra, shrb, shrsel, true);
				sc = dist(rng) % 2;
				shrres = shrres_vec[sc];
				for (uint32_t j = 0; j < nvals; j++){
					if(sc == 1){
						verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? bvec[j] : avec[j];
					}
					else{
						verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? avec[j] : bvec[j];
					}
				}
				break;
			case OP_UNIV:
				op = dist(rng) % TTSIZE;
				shrres = circ->PutUniversalGate(shra, shrb, op);
				for (uint32_t j = 0; j < nvals; j++){
					verifyvec[j] = 0;
					for(uint32_t k = 0; k < bitlen; k++){
						xbit = (avec[j]>>k) & 0x01;
						ybit = (bvec[j]>>k) & 0x01;
						verifyvec[j] |= ((TRUTH_TABLE[op][(xbit << 1) | ybit]) << k);
					}
				}
				break;
			 /*case OP_AND_VEC:
				for(uint32_t j = 0; j < bitlen; j++) {
					 sa[j] = (uint8_t) (dist(rng) & 0x01);
					 sb[j] = (uint8_t) (dist(rng) & 0x01);
				}
				shrsel = circ->PutXORGate(circ->PutINGate(1, sa, bitlen, SERVER), circ->PutINGate(1, sb, bitlen, CLIENT));
				shrres = circ->PutXORGate(shra, shrb);
				shrres = circ->PutANDVecGate(shra, shrsel);
				//shrres = circ->PutMUXGate(shra, shrb, shrsel);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? 0: avec[j]^bvec[j];
				break;

			 break;*/
			 case OP_Y2B:
				 shrres = circ->PutADDGate(shra, shrb);
				 bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				 shrres = bc->PutY2BGate(shrres);
				 shrres = bc->PutMULGate(shrres, shrres);
				 circ = bc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
				 break;
			case OP_B2A:
				 shrres = circ->PutADDGate(shra, shrb);
				 ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				 shrres = ac->PutB2AGate(shrres);
				 shrres = ac->PutMULGate(shrres, shrres);
				 circ = ac;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
				 break;
			case OP_B2Y:
				 shrres = circ->PutADDGate(shra, shrb);
				 yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				 shrres = yc->PutB2YGate(shrres);
				 shrres = yc->PutMULGate(shrres, shrres);
				 circ = yc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
				 break;
			case OP_A2Y:
				 shrres = circ->PutMULGate(shra, shrb);
				 yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				 shrres = yc->PutA2YGate(shrres);
				 shrres = yc->PutADDGate(shrres, shrres);
				 circ = yc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] * bvec[j]) + (avec[j] * bvec[j]);
				 break;
			case OP_A2B:
				 shrres = circ->PutMULGate(shra, shrb);
				 bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				 shrres = bc->PutA2BGate(shrres, sharings[S_YAO]->GetCircuitBuildRoutine());
				 shrres = bc->PutADDGate(shrres, shrres);
				 circ = bc;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] * bvec[j]) + (avec[j] * bvec[j]);
				 break;
			case OP_Y2A:
				 shrres = circ->PutMULGate(shra, shrb);
				 ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				 shrres = ac->PutY2AGate(shrres, sharings[S_BOOL]->GetCircuitBuildRoutine());
				 shrres = ac->PutADDGate(shrres, shrres);
				 circ = ac;
				 for (uint32_t j = 0; j < nvals; j++)
					 verifyvec[j] = (avec[j] * bvec[j]) + (avec[j] * bvec[j]);
				 break;
			/*case OP_AND_VEC:
				 shra = circ->PutCombinerGate(shra);
				 //shrb = circ->PutCombinerGate(shrb);
				 shrres = circ->PutANDVecGate(shra, shrb);
				 //shrres = circ->PutANDGate(shra, shrb);
				 shrres = circ->PutSplitterGate(shrres);
				 verify = (b&0x01) * a;
				 break;*/
			default:
				shrres = circ->PutADDGate(shra, shrb);
				for (uint32_t j = 0; j < nvals; j++)
					verifyvec[j] = avec[j] + bvec[j];
				break;
		}
		shrout = circ->PutOUTGate(shrres, ALL);

		party->ExecCircuit();

		// this allocates buffer put into cvec with calloc
		shrout->get_clear_value_vec(&cvec, &tmpbitlen, &tmpnvals);

		std::stringstream ss;
		ss << get_role_name(role) << " vector operation " << m_tAllOps[operation].opname << ", run = " << r
			<< ": values: a = ";
		for(uint32_t j = 0; j < nvals / sizeof(uint32_t); j++) {
			ss << avec[j];
		}
		ss << ", b = ";
		for(uint32_t j = 0; j < nvals / sizeof(uint32_t); j++) {
			ss << bvec[j];
		}
		ss << ", SFE result = ";
		for(uint32_t j = 0; j < tmpnvals / sizeof(uint32_t); j++) {
			ss << cvec[j];
		}
		ss << ", verify = ";
		for(uint32_t j = 0; j < nvals / sizeof(uint32_t); j++) {
			ss << verifyvec[j];
		}
		ss << " tmpnvals = " << tmpnvals << " nvals = " << nvals;
		bool all_tests_passed = tmpnvals == nvals;
		boost_test_mutex.lock();
		BOOST_TEST(tmpnvals == nvals, ss.str());
		boost_test_mutex.unlock();
		for (uint32_t j = 0; j < nvals; j++) {
			if(all_tests_passed) {
				all_tests_passed = verifyvec[j] == cvec[j];
				boost_test_mutex.lock();
				BOOST_TEST(verifyvec[j] == cvec[j], ss.str());
				boost_test_mutex.unlock();
			} else {
				break;
			}
		}
		party->Reset();
		free(cvec);
	}

	free(sa);
	free(sb);
	free(avec);
	free(bvec);
	free(verifyvec);

}

BOOST_DATA_TEST_CASE(vector_operation_test, boost::unit_test::data::xrange(sizeof(m_tAllOps) / sizeof(aby_ops_t)), operation) {
  std::thread ct(test_vector_ops, operation, client_party, bitlen, nvals, num_test_runs, CLIENT, client_dist, client_rng);
  std::thread st(test_vector_ops, operation, server_party, bitlen, nvals, num_test_runs, SERVER, server_dist, server_rng);

  ct.join();
  st.join();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(standard_operation_tests, TestParameters)

void test_standard_ops(uint32_t operation, ABYParty* party, uint32_t bitlen, uint32_t num_test_runs,
		e_role role,  std::uniform_int_distribution<uint64_t> dist, MyRNG rng) {
	uint32_t a = 0, b = 0, c, verify, sa, sb, sc, xbit, ybit, op;
	share *shra, *shrb, *shrres, *shrout, *shrsel;
	share **shrres_vec;
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit *bc, *yc, *ac;

	for (uint32_t r = 0; r < num_test_runs; r++) {
			Circuit* circ = sharings[m_tAllOps[operation].sharing]->GetCircuitBuildRoutine();
			a = (uint32_t) dist(rng) % ((uint64_t) 1<<bitlen);
			b = (uint32_t) dist(rng) % ((uint64_t) 1<<bitlen);

			shra = circ->PutINGate(a, bitlen, SERVER);
			shrb = circ->PutINGate(b, bitlen, CLIENT);

			switch (m_tAllOps[operation].op) {
			case OP_IO:
				shrres = shra;
				verify = a;
				break;
			case OP_ADD:
				shrres = circ->PutADDGate(shra, shrb);
				verify = a + b;
				break;
			case OP_SUB:
				shrres = circ->PutSUBGate(shra, shrb);
				verify = a - b;
				break;
			case OP_MUL:
				shrres = circ->PutMULGate(shra, shrb);
				verify = a * b;
				break;
			case OP_XOR:
				shrres = circ->PutXORGate(shra, shrb);
				verify = a ^ b;
				break;
			case OP_AND:
				shrres = circ->PutANDGate(shra, shrb);
				verify = a & b;
				break;
			case OP_CMP:
				shrres = circ->PutGTGate(shra, shrb);
				verify = a > b;
				break;
			case OP_EQ:
				shrres = circ->PutEQGate(shra, shrb);
				verify = a == b;
				break;
			case OP_MUX:
				sa = dist(rng) % 2;
				sb = dist(rng) % 2;
				shrsel = circ->PutXORGate(circ->PutINGate(sa, 1, SERVER), circ->PutINGate(sb, 1, CLIENT));
				shrres = circ->PutMUXGate(shra, shrb, shrsel);
				verify = (sa ^ sb) == 0 ? b : a;
				break;
			case OP_X:
				sa = dist(rng) % 2;
				sb = dist(rng) % 2;
				shrsel = circ->PutXORGate(circ->PutINGate(sa, 1, SERVER), circ->PutINGate(sb, 1, CLIENT));
				shrres_vec = circ->PutCondSwapGate(shra, shrb, shrsel, false);
				sc = dist(rng) % 2;
				shrres = shrres_vec[sc];
				if(sc == 1){
					verify = (sa ^ sb) == 0 ? b : a;
				}
				else{
					verify = (sa ^ sb) == 0 ? a : b;
				}
				break;
			case OP_UNIV:
				op = dist(rng) % TTSIZE;
				shrres = circ->PutUniversalGate(shra, shrb, op);
				verify = 0;
				for(uint32_t j = 0; j < bitlen; j++) {
					xbit = (a>>j) & 0x01;
					ybit = (b>>j) & 0x01;
					verify |= ((TRUTH_TABLE[op][(xbit << 1) | ybit]) << j);
				}
				break;
			case OP_Y2B:
				shrres = circ->PutADDGate(shra, shrb);
				bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				shrres = bc->PutY2BGate(shrres);
				shrres = bc->PutMULGate(shrres, shrres);
				circ = bc;
				verify = (a + b) * (a + b);
				break;
			case OP_B2A:
				shrres = circ->PutADDGate(shra, shrb);
				ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				shrres = ac->PutB2AGate(shrres);
				shrres = ac->PutMULGate(shrres, shrres);
				circ = ac;
				verify = (a + b) * (a + b);
				break;
			case OP_B2Y:
				shrres = circ->PutADDGate(shra, shrb);
				yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				shrres = yc->PutB2YGate(shrres);
				shrres = yc->PutMULGate(shrres, shrres);
				circ = yc;
				verify = (a + b) * (a + b);
				break;
			case OP_A2Y:
				shrres = circ->PutMULGate(shra, shrb);
				yc = sharings[S_YAO]->GetCircuitBuildRoutine();
				shrres = yc->PutA2YGate(shrres);
				shrres = yc->PutADDGate(shrres, shrres);
				circ = yc;
				verify = (a * b) + (a * b);
				break;
			case OP_A2B:
				shrres = circ->PutADDGate(shra, shrb);
				bc = sharings[S_BOOL]->GetCircuitBuildRoutine();
				shrres = bc->PutA2BGate(shrres, sharings[S_YAO]->GetCircuitBuildRoutine());
				shrres = bc->PutMULGate(shrres, shrres);
				circ = bc;
				verify = (a + b) * (a + b);
				break;
			case OP_Y2A:
				shrres = circ->PutMULGate(shra, shrb);
				ac = sharings[S_ARITH]->GetCircuitBuildRoutine();
				shrres = ac->PutY2AGate(shrres, sharings[S_BOOL]->GetCircuitBuildRoutine());
				shrres = ac->PutADDGate(shrres, shrres);
				circ = ac;
				verify = (a * b) + (a * b);
				break;
			case OP_AND_VEC:
				shra = circ->PutCombinerGate(shra);
				shrres = circ->PutANDVecGate(shra, shrb);
				shrres = circ->PutSplitterGate(shrres);
				verify = (b & 0x01) * a;
				break;
			default:
				shrres = circ->PutADDGate(shra, shrb);
				verify = a + b;
				break;
			}
			shrout = circ->PutOUTGate(shrres, ALL);
			party->ExecCircuit();

			c = shrout->get_clear_value<uint32_t>();
			std::stringstream ss;
			ss << get_role_name(role) << " standard operation " << m_tAllOps[operation].opname << ", run = " << r
				<< ": values: a = " << a << ", b = " << b << ", SFE result = " << c << ", verify = " << verify;
			boost_test_mutex.lock();
			BOOST_TEST(verify == c, ss.str());
			boost_test_mutex.unlock();
			party->Reset();
	}
}

BOOST_DATA_TEST_CASE(standard_operation_test, boost::unit_test::data::xrange(sizeof(m_tAllOps) / sizeof(aby_ops_t)), operation) {
  std::thread ct(test_standard_ops, operation, client_party, bitlen, num_test_runs, CLIENT, client_dist, client_rng);
  std::thread st(test_standard_ops, operation, server_party, bitlen, num_test_runs, SERVER, server_dist, server_rng);

  ct.join();
  st.join();
}

BOOST_AUTO_TEST_SUITE_END()
