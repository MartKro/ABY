/**
 \file 		aescircuit.h
 \author	Martin Kromm(martin.kromm@stud.tu-darmstadt.de),
 					derived from aes_test.cpp by michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of the certification paper
 */

#ifndef __CERTIFICATION_H_
#define __CERTIFICATION_H_

#include "../../aes/common/aescircuit.h"

class BooleanCircuit;

const char SIGN_COMPRESS[] = "SHA256";

static const char* TEST_VERIFICATION_KEY = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp5L1YB/ZPJQUV+tEti//
JMXtekSoBC8c1HMM1thfHj05aQes2VH/fEaAcW9LFViMD5KKwwvrfieOqRowaS7X
GMHVsZqhHHEYl/I7RSmGAmQgne0cL+Hjzuf3gpnlisfA+uRgIDTJWdIPaEGrbyaJ
Y3L7TiIFob3fYX+R6eUYier2CvCzSa3CyNLyJDaByRw4ktEgFXoa9nFebkrm+bgq
RF0tliqlRaVORBQwUieG1AOtUfz7NpykGsD+1sh8Q4BEpF+kcQ3Uw32oJeWOfuTi
kbeyPiCXNeShcOObLUOeLaVCvecsROQEVHkJkJ0CLSc3YtEEMe1RHsjOYvr8zJV2
MQIDAQAB
-----END PUBLIC KEY-----)";

//Testing functions
//void verify_AES_encryption(uint8_t* input, uint8_t* key, uint32_t nvals, uint8_t* out, crypto* crypt);
/**
 \param		role the role of the user; possible roles: "CLIENT" and "SERVER"
 \param		adress the adress of the server the client connects to
 \param 	port the port of the server the client connects to
 \param		seclvl	the definition of the security level the SFE should be using, see on <ENCRYPTO_utils/crypto/crypto.h>
				to get more information
 \param		nvals the amount of concurrent encryptions to be calculated
 \param		nthreads the amount of threads used
 \param 		mt_alg the Oblivious Extension algorithm to be used; see e_mt_gen_alg in the ABYConstants.h for possible algorithms
 \param		verbose if true some output values will be suppressed for printing; default is false
*/
int32_t test_certification(e_role role, const std::string& address, uint16_t port, const std::string& certadress,
        uint16_t certport, seclvl seclvl, uint32_t nvals, uint32_t nthreads, bool verbose = false);

void rsa_verify(EVP_PKEY* vkey, const uint8_t* sig, uint32_t slen, const uint8_t* msg, uint32_t mlen);

//share* PutSIMDConsGate(uint32_t nvals, uint8_t* val, uint32_t bitlen);

#endif /* __CERTIFICATION_H_ */
