#include "./operation_tests.h"

OperationThread::OperationThread(e_role role, e_sharing sharing_type, uint32_t num_test_runs) :
		role(role), sharing_type(sharing_type), num_test_runs(num_test_runs) {
	if(role == CLIENT) {
		party = ABYPartyTestParameters::GetABYPartyTestParameters()->client_party;
		rng = ABYPartyTestParameters::GetABYPartyTestParameters()->client_rng;
	} else {
		party = ABYPartyTestParameters::GetABYPartyTestParameters()->server_party;
		rng = ABYPartyTestParameters::GetABYPartyTestParameters()->server_rng;
	}
}

void OperationThread::performTest() {
	for(currentRun = 0; currentRun < num_test_runs; currentRun++) {
		try {
			instanziateTest();
			calculateExpected();
			performSFEOperation();
			executeSFE();
			evaluateTest();
		} catch(AssertException& e) {
			
		}
		cleanUpRun();
	}
}

VectorOperationThread::VectorOperationThread(e_role role, e_sharing sharing_type, uint32_t bitlen, uint32_t nvals) :
		OperationThread(role, sharing_type), bitlen(bitlen), nvals(nvals) {
	calculateVecLen();
	avec = (uint32_t*) malloc(veclen * sizeof(uint32_t));
	bvec = (uint32_t*) malloc(veclen * sizeof(uint32_t));
	cvec = nullptr;
	verifyvec = (uint32_t*) malloc(veclen * sizeof(uint32_t));
}

VectorOperationThread::~VectorOperationThread() {
	free(avec);
	free(bvec);
	free(verifyvec);
}

uint32_t VectorOperationThread::divCeil(uint32_t value, uint32_t d) {
	uint32_t div = value / d;
	if(value % d != 0) {
		div++;
	}
	return div;
}

uint32_t VectorOperationThread::maskNumber(uint32_t number, uint32_t value) {
	uint64_t value_mod = value % 32;
	if(value_mod == 0) {
		return number;
	} else {
		return number & ((((uint64_t) 1) << value_mod) - 1);
	}
}

void VectorOperationThread::maskVec(uint32_t* vec) {
	uint32_t one_len = divCeil32(bitlen);
	for(uint32_t i = 0; i < nvals; i++) {
		uint32_t first_vec = i * one_len;
		vec[first_vec] = maskNumber(vec[first_vec], bitlen);
	}
}

void VectorOperationThread::instanziateTest() {
	OperationThread::instanziateTest();
	for (uint32_t j = 0; j < veclen; j++) {
		avec[j] = (uint8_t) ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng);
		bvec[j] = (uint8_t) ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng);
	}
	maskVec(avec);
	maskVec(bvec);
	shra = circ->PutSIMDINGate(nvals, avec, bitlen, SERVER);
	shrb = circ->PutSIMDINGate(nvals, bvec, bitlen, CLIENT);
}

void VectorOperationThread::evaluateTest() {
	// this allocates buffer put into cvec with calloc
	shrout->get_clear_value_vec(&cvec, &tmpbitlen, &tmpnvals);
	std::string printString = makePrintString();
			
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
	EXPECT_EQ(tmpnvals, nvals) << printString;
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
	testTmpBitlen(printString);
	bool all_tests_passed = true;
	for (uint32_t j = 0; j < veclen; j++) {
		//avoid printing multiple times
		if(all_tests_passed) {
			all_tests_passed = verifyvec[j] == cvec[j];
			ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
			EXPECT_EQ(cvec[j], verifyvec[j]) << printString;
			ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
		} else {
			break;
		}
	}
}

std::string VectorOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << avec[j];
	}
	ss << ", b = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << bvec[j];
	}
	ss << ", SFE result = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << cvec[j];
	}
	ss << ", verify = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << verifyvec[j];
	}
	ss << " nvals = " << nvals;
	return ss.str();
}

void VectorOperationThread::testTmpBitlen(std::string& printString) {
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
	EXPECT_EQ(tmpbitlen, bitlen) << printString;
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
}

void ConverterVectorOperationThread::performSFEOperation() {
	shrbefore = circ->PutADDGate(shra, shrb);
	circ_after = party->GetSharings()[sharing_type_after]->GetCircuitBuildRoutine();
	shrafter = converterOperation();
	shrres = circ_after->PutMULGate(shrafter, shrafter);
}

void ConverterVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < nvals; j++) {
		verifyvec[j] = (avec[j] + bvec[j]) * (avec[j] + bvec[j]);
	}
}

void StandardOperationThread::instanziateTest() {
	OperationThread::instanziateTest();
	a = (uint32_t) (ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) & ((1<<bitlen) - 1));
	b = (uint32_t) (ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) & ((1<<bitlen) - 1));
	shra = circ->PutINGate(a, bitlen, SERVER);
	shrb = circ->PutINGate(b, bitlen, CLIENT);
}

void StandardOperationThread::evaluateTest() {
	c = shrout->get_clear_value<uint32_t>();

	std::string printString = makePrintString();
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
	EXPECT_EQ(verify, c) << printString;
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
}

std::string StandardOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = " <<
		a << ", b = " << b << ", SFE result = " << c << ", verify = " << verify;
	return ss.str();
}

void ConverterStandardOperationThread::performSFEOperation() {
	shrbefore = circ->PutADDGate(shra, shrb);
	circ_after = party->GetSharings()[sharing_type_after]->GetCircuitBuildRoutine();
	shrafter = converterOperation();
	shrres = circ_after->PutMULGate(shrafter, shrafter);
}
