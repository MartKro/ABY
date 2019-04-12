if(ABY_BUILD_TESTS)
    enable_testing()
    add_executable(operations_test
        framework_tests.cpp
        operation_tests.cpp
        core_vector_operation_tests.cpp
        core_standard_operation_tests.cpp
        ../abyparty_test_environment/aby_test_environment.cpp
    )
    target_link_libraries(operations_test ABY::aby ENCRYPTO_utils::encrypto_utils gtest)
    target_compile_options(operations_test PRIVATE "-Wall" "-Wextra")
endif()

if(ABY_BUILD_TEST_EXE)
    add_executable(examples_test
        examples_tests.cpp
        operation_tests.cpp
        ../abyparty_test_environment/aby_test_environment.cpp
        ../../examples/aes/common/aescircuit.cpp
        ../../examples/aes/test/aes_gtest.cpp
    )
    target_link_libraries(examples_test ABY::aby ENCRYPTO_utils::encrypto_utils gtest)
    target_compile_options(examples_test PRIVATE "-Wall" "-Wextra")
endif()
