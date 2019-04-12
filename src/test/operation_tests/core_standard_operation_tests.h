#ifndef __CORE_STANDARD_OPERATION_TESTS_H__
#define __CORE_STANDARD_OPERATION_TESTS_H__

#include "./operation_tests.h"

class IOStandardOperationThread : public StandardOperationThread {
	public:
		IOStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = shra;
		}

		inline void calculateExpected() override {
			verify = a;
		}

		std::string makePrintString() override;
};

class AddStandardOperationThread : public StandardOperationThread {
	public:
		AddStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutADDGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a + b;
		}
};

class SubStandardOperationThread : public StandardOperationThread {
	public:
		SubStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutSUBGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a - b;
		}
};

class MulStandardOperationThread : public StandardOperationThread {
	public:
		MulStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutMULGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a * b;
		}
};

class XorStandardOperationThread : public StandardOperationThread {
	public:
		XorStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutXORGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a ^ b;
		}
};

class AndStandardOperationThread : public StandardOperationThread {
	public:
		AndStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutANDGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a & b;
		}
};

class CmpStandardOperationThread : public StandardOperationThread {
	public:
		CmpStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutGTGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a > b;
		}
};

class EqStandardOperationThread : public StandardOperationThread {
	public:
		EqStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutEQGate(shra, shrb);
		}

		inline void calculateExpected() override {
			verify = a == b;
		}
};

class MuxStandardOperationThread : public StandardOperationThread {
	public:
		MuxStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		void instanziateTest() override;

		void performSFEOperation() override;

		inline void calculateExpected() override {
			verify = ((sa ^ sb) == 0 ? b : a);
		}

		std::string makePrintString() override;

	protected:
		share* shrsa;
		share* shrsb;
		share* shrsel;
		uint32_t sa;
		uint32_t sb;
};

class XStandardOperationThread : public StandardOperationThread {
	public:
		XStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		void instanziateTest() override;

		void performSFEOperation() override;

		void calculateExpected() override;

		std::string makePrintString() override;

	protected:
		share* shrsa;
		share* shrsb;
		share* shrsel;
		share** shrres_vec;
		uint32_t sa;
		uint32_t sb;
		uint32_t sc;
};

class UnivStandardOperationThread : public StandardOperationThread {
	public:
		UnivStandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type) {

		}

		inline void instanziateTest() override {
			StandardOperationThread::instanziateTest();
			op = ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng) % TTSIZE;
		}

		inline void performSFEOperation() override {
			shrres = circ->PutUniversalGate(shra, shrb, op);
		}

		void calculateExpected() override;

		std::string makePrintString() override;

	protected:
		uint32_t op;
		uint32_t xbit;
		uint32_t ybit;
};

#endif //__CORE_STANDARD_OPERATION_TESTS_H__
