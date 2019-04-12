#ifndef __ASSERTHANDLING_H__
#define __ASSERTHANDLING_H__

#include <string>

#ifdef GOOGLETEST_ON
    #include <gtest/gtest.h>
    #include <iostream>
    #include <exception>
#else
    #include <cassert>
#endif

#ifdef GOOGLETEST_ON
    struct AssertException : public std::exception {
        const char * what () const throw () {
            return "Assertion error";
        }
    };
#endif

inline void verify_assert(bool statement) {
    #ifdef GOOGLETEST_ON
        EXPECT_TRUE(statement);
    #else
        assert(statement);
    #endif
}

inline void precondition_assert(bool statement) {
    #ifdef GOOGLETEST_ON
        if(!statement) {
            EXPECT_TRUE(false);
            throw AssertException();
        }
    #else
        assert(statement);
    #endif
}


//void verify_assert(bool statement, std::string& print) {
//    #ifdef GOOGLETEST_ON
//        ASSERT_TRUE(statement);
//    #else
//        assert(statement);
//    #endif
//}

//void precondition_assert(bool statement, std::string& print) {
//    #ifdef GOOGLETEST_ON
//        ASSERT_TRUE(statement);
//    #else
//        assert(statement);
//    #endif
//}

#endif //__ASSERTHANDLING_H__