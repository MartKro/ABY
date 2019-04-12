# The test framework explained

### WARNING
This branch is work in progress and very unstable.

### How the tests are intended to work
* The tests provided here are only for testing the functionallity. DO NOT USE THEM TO BENCHMARK YOUR RESULTS!
* All tests are specified by the OperationThread base class. The OperationThread class is a view of a single party during the execution of the test. The test itself is running the following methods:
1. Constructor: Initialize the needed memory for the variables used to instanziate test variables. Optionally the number of runs can be specified here.
2. instanziateTest: Setup the test values for the variables. Random values are provided using ABYPartyTestParameters::GetABYPartyTestParameters()->dist(rng). Input these random values into the shares shra and shrb using PutINGate, PutSIMDINGate or PutCONSGate.
3. calculateExpected: Calculate the expected result of the calculation.
4. performSFEOperation: Calculate the operation using the ABY framework given the input shares shra and shrb. Put the result of the operations into shrres.
5. evaluateTest: Compare the expected results with the result of the ABY framework. Use the Google Test macros EXPECT_TRUE(bool) or EXPECT_EQ(value1, value2) to compare results.
6. makePrintString: Helper method for printing values in case tests fail. Give the result the Google Test macros using << (EXPECT_EQ(value1, value2) << makePrintString()).
* As default all tests run multiple times.

### The VectorOperationThread and the StandardOperationThread
* The VectorOperationThread and StandardOperationThread are derived classes of the OperationThread class. They provide some default implementations of the routine above.
* The StandardOperationThread class works on aby operations with nvals exactly 1 and exactly 32 bits. Some random inputs a and b are instanziated by the instanziateTest method. The user has to implement the calculateExpected method which gives the expected result to the variable verify and the performSFEOperation specified as above.
* The StandardOperationThread class works on aby operations with any nvals and any bitlen. Some random inputs veca and vecb are instanziated by the instanziateTest method. The user has to implement the calculateExpected method which gives the expected result to the variable verify and the performSFEOperation specified as above.
* If the bitlen or the nvals values are unspecified, then the constants provided by the vector_default for the VectorOperationThread and standard_default for the StandardOperationThread are used.

### Create the tests using the OperationThread method
* A macro OPERATIONTEST(testName, sharing, className) is provided. Assuming className is the name of the class derived by the OperationThread class you want to test, the macro is handling the tests for you.
* You have to define a main yourself since you also need to instanziate an enviroment called ABYPartyTestParameters.
* The ABYPartyTestParameters environment is used to handle the ABYParty settings the user wants to use in the tests and provides the setups for the ABYParty class which are then used by the OperationThread classes. For every test main you must provide Google Test the envoirenment ABYPartyTestParameters before starting the tests.