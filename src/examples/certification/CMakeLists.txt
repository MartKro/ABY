
add_executable(certification_test certification_test.cpp common/certification.cpp ../aes/common/aescircuit.cpp)
target_link_libraries(certification_test ABY::aby ENCRYPTO_utils::encrypto_utils)

add_executable(certification_authority_test certification_authority_test.cpp ../aes/common/aescircuit.cpp)
target_link_libraries(certification_authority_test ABY::aby ENCRYPTO_utils::encrypto_utils)

