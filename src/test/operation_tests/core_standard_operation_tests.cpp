#include "./core_standard_operation_tests.h"

std::string IOStandardOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = " <<
		a << ", SFE result = " << c;
	return ss.str();
}

void MuxStandardOperationThread::instanziateTest() {
	StandardOperationThread::instanziateTest();
	sa = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % 2;
	sb = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % 2;
	shrsa = circ->PutINGate(sa, 1, SERVER);
	shrsb = circ->PutINGate(sb, 1, CLIENT);
}

void MuxStandardOperationThread::performSFEOperation() {
	shrsel = circ->PutXORGate(shrsa, shrsb);
	shrres = circ->PutMUXGate(shra, shrb, shrsel);
}

std::string MuxStandardOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = " <<
		a << ", b = " << b << " sa = " << sa << " sb = " << sb << ", SFE result = " << c <<
		", verify = " << verify;
	return ss.str();
}

void XStandardOperationThread::instanziateTest() {
	StandardOperationThread::instanziateTest();
	sa = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % 2;
	sb = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % 2;
	sc = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % 2;
	shrsa = circ->PutINGate(sa, 1, SERVER);
	shrsb = circ->PutINGate(sb, 1, CLIENT);		
}

void XStandardOperationThread::performSFEOperation() {
	shrsel = circ->PutXORGate(shrsa, shrsb);
	shrres_vec = circ->PutCondSwapGate(shra, shrb, shrsel, false);
	shrres = shrres_vec[sc];
}

void XStandardOperationThread::calculateExpected() {
	if(sc == 1){
		verify = (sa ^ sb) == 0 ? b : a;
	} else{
		verify = (sa ^ sb) == 0 ? a : b;
	}
}

std::string XStandardOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = " <<
		a << ", b = " << b << " sa = " << sa << " sb = " << sb << " sc = " << sc <<
		", SFE result = " << c << ", verify = " << verify;
	return ss.str();
}

void UnivStandardOperationThread::calculateExpected() {
	verify = 0;
	for(uint32_t j = 0; j < bitlen; j++) {
		xbit = (a>>j) & 0x01;
		ybit = (b>>j) & 0x01;
		verify |= ((TRUTH_TABLE[op][(xbit << 1) | ybit]) << j);
	}
}

std::string UnivStandardOperationThread::makePrintString() {
	std::stringstream ss;
	ss << get_role_name(role) << ", run = " << currentRun << ": values: a = " <<
		a << ", b = " << b << ", op = " << op << " xbit = " << xbit << " ybit = " << ybit <<
		", SFE result = " << c << ", verify = " << verify;
	return ss.str();
}
