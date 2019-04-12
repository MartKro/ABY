#include "./aes_gtest.h"
#include <ENCRYPTO_utils/cbitvector.h>

AESCircuitThread::AESCircuitThread(e_role role, e_sharing sharing_type, uint32_t nvals) :
        OperationThread(role, sharing_type), nvals(nvals), use_vec_ands(false) {
            crypt = new crypto(
				ABYPartyTestParameters::GetABYPartyTestParameters()->slvl.symbits,
				(uint8_t*) const_seed
			);
            aes_test_key = (uint8_t*) malloc(sizeof(uint8_t) * AES_KEY_BYTES);
			aes_test_input = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES * nvals);
			aes_test_key_expanded = (uint8_t*) malloc(sizeof(uint8_t) * AES_EXP_KEY_BYTES * nvals);
			aes_expected_verify = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES * nvals);
}

AESCircuitThread::AESCircuitThread(e_role role, e_sharing sharing_type) :
        AESCircuitThread(role, sharing_type, vector_default.nvals) {
            
}

AESCircuitThread::~AESCircuitThread() {
    delete crypt;
	free(aes_test_input);
	free(aes_test_key);
	free(aes_test_key_expanded);
}

void AESCircuitThread::instanziateTest() {
    OperationThread::instanziateTest();
	for(uint32_t i = 0; i < AES_KEY_BYTES; i++) {
		aes_test_key[i] = (uint8_t) ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng);
	}
	for(uint32_t i = 0; i < AES_BYTES * nvals; i++) {
		aes_test_input[i] = (uint8_t) ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng);
	}
	ExpandKey(aes_test_key_expanded, aes_test_key);
	shra = circ->PutSIMDINGate(nvals, aes_test_input, AES_BITS, CLIENT);
	shrb = circ->PutINGate(aes_test_key, AES_KEY_BITS, SERVER);
}

void AESCircuitThread::calculateExpected() {
	verify_AES_encryption(aes_test_input, aes_test_key, nvals, aes_expected_verify, crypt);
}

void AESCircuitThread::performSFEOperation() {
	s_key_expanded = BuildKeyExpansion(shrb, (BooleanCircuit*) circ, false);
	s_key_repeated = circ->PutRepeaterGate(nvals, s_key_expanded);
	shrres = BuildAESCircuit(shra, s_key_repeated, (BooleanCircuit*) circ, use_vec_ands);
	shrout = circ->PutOUTGate(shrres, ALL);
}

void AESCircuitThread::evaluateTest() {
	aes_sfe_output = shrout->get_clear_value_ptr();

	std::string printString = makePrintString();
	bool all_tests_passed = true;
	for (uint32_t j = 0; j < AES_BYTES; j++) {
		//avoid printing multiple times
		if(all_tests_passed) {
			all_tests_passed = aes_sfe_output[j] == aes_expected_verify[j];
			ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
			EXPECT_EQ(aes_sfe_output[j], aes_expected_verify[j]) << printString;
			ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
		} else {
			break;
		}
	}
}

std::string AESCircuitThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: input = ";
	for(uint32_t j = 0; j < AES_BYTES; j++) {
		ss << aes_test_input[j];
	}
	ss << ", key = ";
	for(uint32_t j = 0; j < AES_KEY_BYTES; j++) {
		ss << aes_test_key[j];
	}
	ss << ", expanded key = ";
	for(uint32_t j = 0; j < AES_EXP_KEY_BYTES; j++) {
		ss << aes_test_key_expanded[j];
	}
	ss << ", SFE result = ";
	for(uint32_t j = 0; j < AES_BYTES; j++) {
		ss << aes_sfe_output[j];
	}
	ss << ", verify = ";
	for(uint32_t j = 0; j < AES_BYTES; j++) {
		ss << aes_expected_verify[j];
	}
	ss << " nvals = " << nvals;
	return ss.str();
}

void AESCircuitThread::cleanUpRun() {
	OperationThread::cleanUpRun();
	//in future the share memory handling should be done when the ABYParty gets deleted
	//free(s_key_expanded);
	//free(s_key_repeated);
	free(aes_sfe_output);
}

AESVecCircuitThread::AESVecCircuitThread(e_role role, e_sharing sharing_type, uint32_t nvals) :
        AESCircuitThread(role, sharing_type, nvals) {
	use_vec_ands = true;
    pos_even = (uint32_t*) malloc(sizeof(uint32_t) * nvals);
	pos_odd = (uint32_t*) malloc(sizeof(uint32_t) * nvals);
	for(uint32_t i = 0; i < nvals; i++) {
		pos_even[i] = 2*i;
		pos_odd[i] = 2*i+1;
	}
}

AESVecCircuitThread::AESVecCircuitThread(e_role role, e_sharing sharing_type) :
        AESVecCircuitThread(role, sharing_type, vector_default.nvals) {
            
}

AESVecCircuitThread::~AESVecCircuitThread() {
	//free(pos_even);
	//free(pos_odd);
}
