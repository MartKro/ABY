#ifndef _AES_GTEST_H_
#define _AES_GTEST_H_

#include "../../../test/operation_tests/operation_tests.h"
#include "../common/aescircuit.h"

class AESCircuitThread: public OperationThread {
    public:
        AESCircuitThread(e_role role, e_sharing sharing_type, uint32_t nvals);

        AESCircuitThread(e_role role, e_sharing sharing_type);

        virtual ~AESCircuitThread();

        void instanziateTest();
        void performSFEOperation();
	    void calculateExpected();
        void evaluateTest();
	    std::string makePrintString();
        void cleanUpRun();

    protected:
        crypto* crypt;
        uint32_t nvals;
        uint8_t* aes_test_key;
        uint8_t* aes_test_key_expanded;
        uint8_t* aes_test_input;
        uint8_t* aes_sfe_output;
        uint8_t* aes_expected_verify;
        share* s_key_expanded;
        share* s_key_repeated;
        bool use_vec_ands;
};

class AESVecCircuitThread : public AESCircuitThread {
    public:
        AESVecCircuitThread(e_role role, e_sharing sharing_type, uint32_t nvals);

        AESVecCircuitThread(e_role role, e_sharing sharing_type);

        ~AESVecCircuitThread();
};

#endif //_AES_GTEST_H_
