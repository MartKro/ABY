if(ABY_BUILD_EXE)
    add_executable(abytest
        abytest.cpp
        ../examples/aes/common/aescircuit.cpp
        ../examples/sha1/common/sha1_circuit.cpp
        ../examples/psi_scs/common/sort_compare_shuffle.cpp
        ../examples/psi_scs/common/WaksmanPermutation.cpp
        ../examples/psi_phasing/common/phasing_circuit.cpp
        ../examples/psi_phasing/common/hashing/simple_hashing.cpp
        ../examples/psi_phasing/common/hashing/cuckoo.cpp
    )
    # might thinking about renaming to interactive test
    target_compile_options(abytest PRIVATE "-Wall" "-Wextra")
    target_link_libraries(abytest ABY::aby ENCRYPTO_utils::encrypto_utils)
endif(ABY_BUILD_EXE)

if(ABY_BUILD_TEST)
    find_package(Boost COMPONENTS unit_test_framework REQUIRED)

    add_executable(operations_test
        operation_tests/operation_tests.cpp
    )
    #linking should be discussed further
    target_include_directories(operations_test PRIVATE ${Boost_INCLUDE_DIRS})
    target_compile_definitions(operations_test PRIVATE "BOOST_TEST_DYN_LINK=1")
    target_link_libraries(operations_test ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})
    target_link_libraries(operations_test ABY::aby ENCRYPTO_utils::encrypto_utils)
    target_compile_options(operations_test PRIVATE "-Wall" "-Wextra")
endif(ABY_BUILD_TEST)
