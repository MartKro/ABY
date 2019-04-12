#ifndef __CORE_VECTOR_OPERATION_TESTS_H__
#define __CORE_VECTOR_OPERATION_TESTS_H__

#include "./operation_tests.h"

class IOVectorOperationThread: public VectorOperationThread {
	public:
		IOVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = shra;
		}

		void calculateExpected() override;

		std::string makePrintString() override;
};

class ConsVectorOperationThread: public VectorOperationThread {
	public:
		ConsVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {
				consvec = (uint32_t*) malloc(sizeof(uint32_t) * divCeil32(bitlen));
		}

		inline ~ConsVectorOperationThread() {
			free(consvec);
		}

		void instanziateTest() override;

		inline void performSFEOperation() override {
			shrres = shrcons;
		}

		void calculateExpected() override;

		std::string makePrintString() override;

	protected:
		uint32_t *consvec;
		share *shrcons;
};

class AddVectorOperationThread: public VectorOperationThread {
	public:
		AddVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutADDGate(shra, shrb);
		}

		void calculateExpected() override;
};

class SubVectorOperationThread: public VectorOperationThread {
	public:
		SubVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutSUBGate(shra, shrb);
		}

		void calculateExpected() override;
};

class MulVectorOperationThread: public VectorOperationThread {
	public:
		MulVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override{
			shrres = circ->PutMULGate(shra, shrb);
		}

		void calculateExpected() override;
};

class XorVectorOperationThread: public VectorOperationThread {
	public:
		XorVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override{
			shrres = circ->PutXORGate(shra, shrb);
		}

		void calculateExpected() override;
};

class AndVectorOperationThread: public VectorOperationThread {
	public:
		AndVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override{
			shrres = circ->PutANDGate(shra, shrb);
		}

		void calculateExpected() override;
};

class CmpVectorOperationThread: public VectorOperationThread {
	public:
		CmpVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutGTGate(shra, shrb);
		}

		void calculateExpected() override;

		void testTmpBitlen(std::string& printString);
};

class EqVectorOperationThread: public VectorOperationThread {
	public:
		EqVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {

		}

		inline void performSFEOperation() override {
			shrres = circ->PutEQGate(shra, shrb);
		}

		void calculateExpected() override;

		void testTmpBitlen(std::string& printString) override;
};

class MuxVectorOperationThread: public VectorOperationThread {
	public:
		MuxVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {
				sa = (uint8_t*) malloc(std::max(nvals, bitlen) * sizeof(uint8_t));
				sb = (uint8_t*) malloc(std::max(nvals, bitlen) * sizeof(uint8_t));
		}

		void instanziateTest() override;

		void performSFEOperation() override;

		void calculateExpected() override;

		//inline void cleanUpRun() override {
		//	VectorOperationThread::cleanUpRun();
			//in future share memory handling should be done when the ABYParty gets deleted
			//free(shrsel);
			//free(shrsa);
			//free(shrsb);
		//}

		std::string makePrintString() override;

		inline ~MuxVectorOperationThread() {
			free(sa);
			free(sb);
		}

	protected:
		uint8_t* sa;
		uint8_t* sb;
		share* shrsa;
		share* shrsb;
		share* shrsel;
};

class XVectorOperationThread: public VectorOperationThread {
	public:
		XVectorOperationThread(e_role role, e_sharing sharing_type) :
			VectorOperationThread(role, sharing_type) {
				sa = (uint8_t*) malloc(std::max(nvals, bitlen) * sizeof(uint8_t));
				sb = (uint8_t*) malloc(std::max(nvals, bitlen) * sizeof(uint8_t));
		}

		void instanziateTest() override;

		void performSFEOperation() override;

		void calculateExpected() override;

		//void cleanUpRun() {
		//	VectorOperationThread::cleanUpRun();
			//in future share memory handling should be done when the ABYParty gets deleted
			//free(shrsel);
			//free(shrsa);
			//free(shrsb);
			//free(shrres_vec[1-sc]);
		//}

		std::string makePrintString() override;

		inline ~XVectorOperationThread() {
			free(sa);
			free(sb);
		}

	protected:
		uint8_t *sa;
		uint8_t *sb;
		uint8_t sc;
		share *shrsa;
		share *shrsb;
		share *shrsel;
		share **shrres_vec;
};

class UnivVectorOperationThread: public VectorOperationThread {
	public:
		UnivVectorOperationThread(e_role role, e_sharing sharing_type);

		inline void instanziateTest() override {
			VectorOperationThread::instanziateTest();
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

#endif //__CORE_VECTOR_OPERATION_TESTS_H__
