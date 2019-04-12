#include "./core_vector_operation_tests.h"

void IOVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j];
	}
}

std::string IOVectorOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << avec[j];
	}
	ss << ", SFE result = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << cvec[j];
	}
	ss << " nvals = " << nvals;
	return ss.str();
}

void ConsVectorOperationThread::instanziateTest() {
	VectorOperationThread::instanziateTest();
	for(uint32_t i = 0; i < divCeil32(bitlen); i++) {
		consvec[i] = (uint32_t) ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng);
	}
	consvec[0] = maskNumber(consvec[0], bitlen);
	shrcons = circ->PutSIMDCONSGate(nvals, consvec, bitlen);
	shrcons->set_max_bitlength(bitlen);
}

void ConsVectorOperationThread::calculateExpected() {
	for (uint32_t i = 0; i < nvals; i++) {
		for(uint32_t j = 0; j < divCeil32(bitlen); j++) {
			verifyvec[i * divCeil32(bitlen) + j] = consvec[j];
		}
	}
}

std::string ConsVectorOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: cons = ";
	for(uint32_t j = 0; j < divCeil32(bitlen); j++) {
		ss << consvec[j];
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

void AddVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] + bvec[j];
	}
}

void SubVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] - bvec[j];
	}
}

void MulVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] * bvec[j];
	}
}

void XorVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] ^ bvec[j];
	}
}

void AndVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] & bvec[j];
	}
}

void CmpVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] > bvec[j];
	}
}

void CmpVectorOperationThread::testTmpBitlen(std::string& printString) {
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
	EXPECT_EQ(tmpbitlen, 1) << printString;
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
}

void EqVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < veclen; j++) {
		verifyvec[j] = avec[j] == bvec[j];
	}
}

void EqVectorOperationThread::testTmpBitlen(std::string& printString) {
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.lock();
	EXPECT_EQ(tmpbitlen, 1) << printString;
	ABYPartyTestParameters::GetABYPartyTestParameters()->test_mutex.unlock();
}

void MuxVectorOperationThread::instanziateTest() {
	VectorOperationThread::instanziateTest();
	for(uint32_t j = 0; j < nvals; j++) {
		sa[j] = (uint8_t) (ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) & 0x01);
		sb[j] = (uint8_t) (ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) & 0x01);
	}
	shrsa = circ->PutSIMDINGate(nvals, sa, 1, SERVER);
	shrsb = circ->PutSIMDINGate(nvals, sb, 1, CLIENT);
}

void MuxVectorOperationThread::performSFEOperation() {
	shrsel = circ->PutXORGate(shrsa, shrsb);
	shrres = circ->PutMUXGate(shra, shrb, shrsel);
}

void MuxVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < nvals; j++) {
		verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? bvec[j] : avec[j];
	}
}

std::string MuxVectorOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << avec[j];
	}
	ss << ", b = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << bvec[j];
	}
	ss << ", sa = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << sa[j];
	}
	ss << ", sb = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << sb[j];
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

void XVectorOperationThread::instanziateTest() {
	VectorOperationThread::instanziateTest();
	for(uint32_t j = 0; j < nvals; j++) {
		sa[j] = (uint8_t) (ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) & 0x01);
		sb[j] = (uint8_t) (ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) & 0x01);
	}
	shrsa = circ->PutSIMDINGate(nvals, sa, 1, SERVER);
	shrsb = circ->PutSIMDINGate(nvals, sb, 1, CLIENT);
}

void XVectorOperationThread::performSFEOperation() {
	shrsel = circ->PutXORGate(shrsa, shrsb);
	shrres_vec = circ->PutCondSwapGate(shra, shrb, shrsel, true);
	sc = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % 2;
	shrres = shrres_vec[sc];
			
}

void XVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < nvals; j++){
		if(sc == 1) {
			verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? bvec[j] : avec[j];
		}
		else {
			verifyvec[j] = (sa[j] ^ sb[j]) == 0 ? avec[j] : bvec[j];
		}
	}
}

std::string XVectorOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << avec[j];
	}
	ss << ", b = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << bvec[j];
	}
	ss << ", sa = ";
	for(uint32_t j = 0; j < nvals; j++) {
		ss << sa[j];
	}
	ss << ", sb = ";
	for(uint32_t j = 0; j < nvals; j++) {
		ss << sb[j];
	}
	ss << ", sc = " << sc;
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

UnivVectorOperationThread::UnivVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

	if(nvals > 32) {
		EXPECT_TRUE(false) << "UnivVectorTest currently does not work with nvals > 32, " <<
			"therefore the test is redone with nvals = 32 AND the test is marked as failed";
		nvals = 32;
	}
}

void UnivVectorOperationThread::calculateExpected() {
	for (uint32_t j = 0; j < nvals; j++){
		verifyvec[j] = 0;
		for(uint32_t k = 0; k < bitlen; k++){
			xbit = (avec[j]>>k) & 0x01;
			ybit = (bvec[j]>>k) & 0x01;
			verifyvec[j] |= ((TRUTH_TABLE[op][(xbit << 1) | ybit]) << k);
		}
	}
}

std::string UnivVectorOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << avec[j];
	}
	ss << ", b = ";
	for(uint32_t j = 0; j < veclen; j++) {
		ss << bvec[j];
	}
	ss << ", op = " << op << " xbit = " << xbit << " ybit = " << ybit;
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
