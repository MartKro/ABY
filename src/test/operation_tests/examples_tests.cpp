#include "../../examples/aes/test/aes_gtest.h"

OPERATIONTEST(aesBoolStandardTest, S_BOOL, AESCircuitThread)
OPERATIONTEST(aesYaoStandardTest, S_YAO, AESCircuitThread)
OPERATIONTEST(aesSplutStandardTest, S_SPLUT, AESCircuitThread)
OPERATIONTEST(aesBoolVectorOptimazitaionTest, S_BOOL, AESVecCircuitThread)
OPERATIONTEST(aesYaoVectorOptimaziationTest, S_YAO, AESVecCircuitThread)
OPERATIONTEST(aesSplutVectorOptimizationTest, S_SPLUT, AESVecCircuitThread)

int main(int argc, char **argv) {
	testing::InitGoogleTest(&argc, argv);
	testing::AddGlobalTestEnvironment(ABYPartyTestParameters::GetABYPartyTestParameters());
	return RUN_ALL_TESTS();
}
