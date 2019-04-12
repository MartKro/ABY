#ifndef __OPERATION_TESTS_H__
#define __OPERATION_TESTS_H__

#define GOOGLETEST_ON

#include <gtest/gtest.h>

#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/circuit.h"
#include "../../abycore/circuit/share.h"
#include "../../abycore/sharing/sharing.h"

#include "../abyparty_test_environment/aby_test_environment.h"

static const uint32_t TTSIZE = 16;
static const uint32_t TRUTH_TABLE[TTSIZE][4]={{0,0,0,0}, {1,0,0,0}, {0,1,0,0}, {1,1,0,0},
		{0,0,1,0}, {1,0,1,0}, {0,1,1,0}, {1,1,1,0},
		{0,0,0,1}, {1,0,0,1}, {0,1,0,1}, {1,1,0,1},
		{0,0,1,1}, {1,0,1,1}, {0,1,1,1}, {1,1,1,1},
};

class OperationThread {
	public:
		OperationThread(e_role role, e_sharing sharing_type, uint32_t num_test_runs);
		OperationThread(e_role role, e_sharing sharing_type) :
			OperationThread(role, sharing_type, ABYPartyTestParameters::GetABYPartyTestParameters()->num_test_runs) {

		}

		inline virtual ~OperationThread() {
			
        }

		void performTest();

		inline virtual void instanziateTest() {
			circ = party->GetSharings()[sharing_type]->GetCircuitBuildRoutine();
		}

		inline virtual void executeSFE() {
			shrout = circ->PutOUTGate(shrres, ALL);
			party->ExecCircuit();
		}

		inline virtual void cleanUpRun() {
			party->Reset();
			//in future the share memory handling should be done when the ABYParty gets deleted
			//free(shra);
			//free(shrb);
			//free(shrres);
			//free(shrout);
		}

		//Define the actual test here
		virtual void calculateExpected() = 0;
		virtual void performSFEOperation() = 0;
		virtual std::string makePrintString() = 0;
		virtual void evaluateTest() = 0;

	protected:
		e_role role;
		e_sharing sharing_type;
		ABYParty* party;
		MyRNG rng;
		Circuit* circ;
		uint32_t currentRun;
		share *shra;
		share *shrb;
		share *shrres;
		share *shrout;
		uint32_t num_test_runs;
};

/**
 *	The following test classes are default tests with the same number of paralell
 *	operations and the same number of bits. Of course it is possible to write 
 *	tests with a different bitlength and different number of operations.
*/
const struct {
	uint32_t bitlen;
	uint32_t nvals;
} vector_default = {32, 65};

class VectorOperationThread : public OperationThread {
	public:
		VectorOperationThread(e_role role, e_sharing sharing_type, uint32_t bitlen, uint32_t nvals);

		VectorOperationThread(e_role role, e_sharing sharing_type) : 
			VectorOperationThread(role, sharing_type, vector_default.bitlen, vector_default.nvals) {

		}

		~VectorOperationThread();

		inline void calculateVecLen() {
			veclen = divCeil32(bitlen) * nvals;
		}

		uint32_t divCeil(uint32_t value, uint32_t d);

		//uint32_t divCeil8(uint32_t value) {
		//	return divCeil(value, 8);
		//}

		inline uint32_t divCeil32(uint32_t value) {
			return divCeil(value, 32);
		}

		uint32_t maskNumber(uint32_t number, uint32_t value);

		void maskVec(uint32_t* vec);

		void instanziateTest();

		void evaluateTest();

		virtual void testTmpBitlen(std::string& printString);

		virtual std::string makePrintString();

		inline void cleanUpRun() {
			OperationThread::cleanUpRun();
			free(cvec);
		}

	protected:
		uint32_t bitlen;
		uint32_t nvals;

		uint32_t *avec;
		uint32_t *bvec;
		uint32_t *cvec;
		uint32_t *verifyvec;

		uint32_t tmpnvals;
		uint32_t tmpbitlen;

		uint32_t veclen;
};

class ConverterVectorOperationThread: public VectorOperationThread {
	public:
		ConverterVectorOperationThread(e_role role, e_sharing sharing_type_before, e_sharing sharing_type_after) :
			VectorOperationThread(role, sharing_type_before), sharing_type_after(sharing_type_after) {
				
		}

		void performSFEOperation() override;

		void calculateExpected() override;

		inline void executeSFE() override {
			circ = circ_after;
			VectorOperationThread::executeSFE();
		}

		//implement these method for converter operations
		virtual share* converterOperation() = 0;

	protected:
		//must be given to the constructor
		e_sharing sharing_type_after;

		share *shrbefore;
		share *shrafter;
		Circuit *circ_after;
};

class Y2BVectorOperationThread: public ConverterVectorOperationThread {
	public:
		Y2BVectorOperationThread(e_role role) : ConverterVectorOperationThread(role, S_YAO, S_BOOL) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutY2BGate(shrbefore);
		}
};

class B2AVectorOperationThread: public ConverterVectorOperationThread {
	public:
		B2AVectorOperationThread(e_role role) : ConverterVectorOperationThread(role, S_BOOL, S_ARITH) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutB2AGate(shrbefore);
		}
};

class B2YVectorOperationThread: public ConverterVectorOperationThread {
	public:
		B2YVectorOperationThread(e_role role) : ConverterVectorOperationThread(role, S_BOOL, S_YAO) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutB2YGate(shrbefore);
		}
};

class A2YVectorOperationThread: public ConverterVectorOperationThread {
	public:
		A2YVectorOperationThread(e_role role) : ConverterVectorOperationThread(role, S_ARITH, S_YAO) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutA2YGate(shrbefore);
		}
};

class A2BVectorOperationThread: public ConverterVectorOperationThread {
	public:
		A2BVectorOperationThread(e_role role) : ConverterVectorOperationThread(role, S_ARITH, S_BOOL) {
				
		}

		inline void instanziateTest() override {
			ConverterVectorOperationThread::instanziateTest();
			yc = party->GetSharings()[S_YAO]->GetCircuitBuildRoutine();
		}

		inline share* converterOperation() override {
			return circ_after->PutA2BGate(shrbefore, yc);
		}

	protected:
		Circuit *yc;
};

class Y2AVectorOperationThread: public ConverterVectorOperationThread {
	public:
		Y2AVectorOperationThread(e_role role) : ConverterVectorOperationThread(role, S_YAO, S_ARITH) {
				
		}

		inline void instanziateTest() override {
			ConverterVectorOperationThread::instanziateTest();
			bc = party->GetSharings()[S_BOOL]->GetCircuitBuildRoutine();
		}

		inline share* converterOperation() override {
			return circ_after->PutY2AGate(shrbefore, bc);
		}

	protected:
		Circuit *bc;
};
const struct {
	uint32_t bitlen;
} standard_default = {32};

class StandardOperationThread : public OperationThread {
	public:
		StandardOperationThread(e_role role, e_sharing sharing_type, uint32_t bitlen) :
			OperationThread(role, sharing_type), bitlen(bitlen) {

		}

		StandardOperationThread(e_role role, e_sharing sharing_type) :
			StandardOperationThread(role, sharing_type, standard_default.bitlen) {

		}

		void instanziateTest();

		void evaluateTest();

		std::string makePrintString();

	protected:
		uint32_t a;
		uint32_t b;
		uint32_t c;
		uint32_t verify;
		uint32_t bitlen;
		//sa, sb, sc, xbit, ybit, op;
		//*shrsel;
		//share **shrres_vec;
		//Circuit *bc, *yc, *ac;
};

class ConverterStandardOperationThread: public StandardOperationThread {
	public:
		ConverterStandardOperationThread(e_role role, e_sharing sharing_type_before, e_sharing sharing_type_after) :
			StandardOperationThread(role, sharing_type_before), sharing_type_after(sharing_type_after) {

		}

		void performSFEOperation() override;

		inline void calculateExpected() override {
			verify = (a + b) * (a + b);
		}

		inline void executeSFE() override {
			circ = circ_after;
			StandardOperationThread::executeSFE();
		}

		//implement these method for converter operations
		virtual share* converterOperation() = 0;

	protected:
		//must be given to the constructor
		e_sharing sharing_type_after;

		share *shrbefore;
		share *shrafter;
		Circuit *circ_after;
};

class Y2BStandardOperationThread: public ConverterStandardOperationThread {
	public:
		Y2BStandardOperationThread(e_role role) :
			ConverterStandardOperationThread(role, S_YAO, S_BOOL) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutY2BGate(shrbefore);
		}
};

class B2AStandardOperationThread: public ConverterStandardOperationThread {
	public:
		B2AStandardOperationThread(e_role role) :
			ConverterStandardOperationThread(role, S_BOOL, S_ARITH) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutB2AGate(shrbefore);
		}
};

class B2YStandardOperationThread: public ConverterStandardOperationThread {
	public:
		B2YStandardOperationThread(e_role role) :
			ConverterStandardOperationThread(role, S_BOOL, S_YAO) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutB2YGate(shrbefore);
		}
};

class A2YStandardOperationThread: public ConverterStandardOperationThread {
	public:
		A2YStandardOperationThread(e_role role) :
			ConverterStandardOperationThread(role, S_ARITH, S_YAO) {
				
		}

		inline share* converterOperation() override {
			return circ_after->PutA2YGate(shrbefore);
		}
};

class A2BStandardOperationThread: public ConverterStandardOperationThread {
	public:
		A2BStandardOperationThread(e_role role) :
			ConverterStandardOperationThread(role, S_ARITH, S_BOOL) {
				
		}

		inline void instanziateTest() override {
			ConverterStandardOperationThread::instanziateTest();
			yc = party->GetSharings()[S_YAO]->GetCircuitBuildRoutine();
		}

		inline share* converterOperation() override {
			return circ_after->PutA2BGate(shrbefore, yc);
		}

	protected:
		Circuit *yc;
};

class Y2AStandardOperationThread: public ConverterStandardOperationThread {
	public:
		Y2AStandardOperationThread(e_role role) :
			ConverterStandardOperationThread(role, S_YAO, S_ARITH) {
				
		}

		inline void instanziateTest() override {
			ConverterStandardOperationThread::instanziateTest();
			bc = party->GetSharings()[S_BOOL]->GetCircuitBuildRoutine();
		}

		inline share* converterOperation() override {
			return circ_after->PutY2AGate(shrbefore, bc);
		}

	protected:
		Circuit *bc;
};

#define OPERATIONTEST(testName, sharing, className) TEST(OperationsTest, testName) {	\
	className *client_vector_thread = new className(CLIENT, sharing);					\
	className *server_vector_thread = new className(SERVER, sharing);						\
	ABYPartyTestParameters::GetABYPartyTestParameters()->pool.AddJob(std::bind(&OperationThread::performTest, client_vector_thread));			\
	ABYPartyTestParameters::GetABYPartyTestParameters()->pool.AddJob(std::bind(&className::performTest, server_vector_thread));			\
	ABYPartyTestParameters::GetABYPartyTestParameters()->pool.WaitAll();																			\
	delete client_vector_thread;															\
	delete server_vector_thread;															\
}

#define OPERATIONCONVERTERTEST(testName, className) TEST(OperationsTest, testName) {	\
	className *client_vector_thread = new className(CLIENT);					\
	className *server_vector_thread = new className(SERVER);						\
	ABYPartyTestParameters::GetABYPartyTestParameters()->pool.AddJob(std::bind(&className::performTest, client_vector_thread));			\
	ABYPartyTestParameters::GetABYPartyTestParameters()->pool.AddJob(std::bind(&className::performTest, server_vector_thread));			\
	ABYPartyTestParameters::GetABYPartyTestParameters()->pool.WaitAll();																			\
	delete client_vector_thread;															\
	delete server_vector_thread;															\
}

#endif //__OPERATION_TESTS_H__
