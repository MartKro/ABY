/**
 \file 		certification_authority_test.cpp
 \author 	Martin Kromm(martin.kromm@stud.tu-darmstadt.de),
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
 \brief		Certification Authority Test class implementation.
 */

//Utility libs
#include "../aes/common/aescircuit.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/socket.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
//#include <openssl/evp.h>
//#include <openssl/rsa.h>
#include <stdio.h>
#include <cstring>
#include <cassert>
#include <iostream>

const char SIGN_COMPRESS[] = "SHA256";

static const char* TEST_SIGNING_KEY = R"(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp5L1YB/ZPJQUV+tEti//JMXtekSoBC8c1HMM1thfHj05aQes
2VH/fEaAcW9LFViMD5KKwwvrfieOqRowaS7XGMHVsZqhHHEYl/I7RSmGAmQgne0c
L+Hjzuf3gpnlisfA+uRgIDTJWdIPaEGrbyaJY3L7TiIFob3fYX+R6eUYier2CvCz
Sa3CyNLyJDaByRw4ktEgFXoa9nFebkrm+bgqRF0tliqlRaVORBQwUieG1AOtUfz7
NpykGsD+1sh8Q4BEpF+kcQ3Uw32oJeWOfuTikbeyPiCXNeShcOObLUOeLaVCvecs
ROQEVHkJkJ0CLSc3YtEEMe1RHsjOYvr8zJV2MQIDAQABAoIBAAbjbZ7D8GQjGir7
CtoKYwyZ7kcmZ1m0rhS1ngN+5XoSvjdpD1vnmP78zu7aylVYTHmfZoDaDpYi/iRJ
ZVANkt37qdMhLhpDM+WbGYCgUlfq0cRsKMp3GKw6sNv3g44O5AnsNV9djCFbFzML
8AYjqWYjJd1yXJTnfzU8zzy0JCwXIXd+2f8sVOPagTxlyCo9EoLMzIBJ/Zb6Qtgl
N2+SR2UTfAa40ThOxoV3Y4YM4SKoP03Oh/AvKFz5TUGIPPYoQtbZ52IyjppodijG
BmKUZQA5g2mFDoHvfX62y6W24wo8rr+55Okwt7tke4509AEeQWNbdVC1d6tIrUGq
RvSPVbkCgYEA12XB2QX4tvkCKIU1EVAbpdN3aV5C0EVAKh00r3ewTssvrmfuY2A4
+G6f/p4IL8PJ0vaXaIRBpJbfWAPWfnsa4qc8fUuYyGeCakl/8Lc8dJJ30wM7qSNp
ZVcwH0JVLRi8gLrCpb+1zxwXtF23DOrLOOKYEnFsOAIMsVRYroZDbrMCgYEAxylt
ztvoWqpuzqqxLxfEorlVmVgkrZ4C2T5EDyRct/6zYPFWrh5wcAm6Cgk6Nv0W4xgi
UaGG2Ry3DuSrDhb2G5BbYtAhKMZ/2BDVcmP/IhuEtI9sPo9YgmZ0WjrkfMISqmgw
cC5crtfQO6SAPIWc8Z04T26Ee62FhGm2lRWjuYsCgYALmhWI5QNyh5MQL6yeFByJ
IAzMhiE/Kpu8KPqPgPjkJZmZ4Us72xD2gK7pfgWe3QLf9BxPquAGR4IcMYi6I1Nd
ZfiiHxJJqRmjM/ZKNvRwqvr9SK1L/PZOWRXkeSQxW6W7oVOerebTEwZL1shnT7ZG
iB380FMt6R5Z5tsn+19idQKBgBYdPokil+lBVW5zO5tcC0R6ScvuIpx4mB5hMJNx
2S3BBU/1XEeXL6rxGYw1vBYRAjKTInRn+B4xdw4bS/cTi55B6DPPom7xo45tSBYc
jl7OKW0XI9DKf+xyzeaa9XX44rOzP/Wk4Du10PRebrLJr0SQzYjcX6+P8+xhBJoH
PhfDAoGBAKHCYMgjsFiba5uqMMe0Je813Jyr93xCIfX8XsOzCii650tIf9RsWDSp
JDQk/H0PhUi8cjQwkhumC7BWaXVWkaBElWndpJDDmaALDciZDXqQ+3fQf8bsIiVI
YoRmjSS7f8jp7Jg+7r6BsGuYtg2aiN0+Gf6P33oAFx+IuD+tF7bU
-----END RSA PRIVATE KEY-----)";

static const char* TEST_VERIFICATION_KEY = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp5L1YB/ZPJQUV+tEti//
JMXtekSoBC8c1HMM1thfHj05aQes2VH/fEaAcW9LFViMD5KKwwvrfieOqRowaS7X
GMHVsZqhHHEYl/I7RSmGAmQgne0cL+Hjzuf3gpnlisfA+uRgIDTJWdIPaEGrbyaJ
Y3L7TiIFob3fYX+R6eUYier2CvCzSa3CyNLyJDaByRw4ktEgFXoa9nFebkrm+bgq
RF0tliqlRaVORBQwUieG1AOtUfz7NpykGsD+1sh8Q4BEpF+kcQ3Uw32oJeWOfuTi
kbeyPiCXNeShcOObLUOeLaVCvecsROQEVHkJkJ0CLSc3YtEEMe1RHsjOYvr8zJV2
MQIDAQAB
-----END PUBLIC KEY-----)";

void rsa_sign(EVP_PKEY* skey, uint8_t** sig, uint32_t* slen, const uint8_t* msg, uint32_t mlen) {
	
    if(*sig) {
		OPENSSL_free(*sig);
	}
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    ctx = EVP_MD_CTX_create();
    if(ctx == NULL) {
		std::cerr << "EVP_MD_CTX_create failed" << std::endl;
		std::exit(1);
    }
        
    const EVP_MD* md = EVP_get_digestbyname(SIGN_COMPRESS);
    if(md == NULL) {
        std::cerr << "EVP_get_digestbyname failed" << std::endl;
        std::exit(1);
    }
        
    int rc = EVP_DigestInit_ex(ctx, md, NULL);
    if(rc != 1) {
        std::cerr << "EVP_DigestInit_ex failed" << std::endl;
        std::exit(1);
    }
        
    rc = EVP_DigestSignInit(ctx, NULL, md, NULL, skey);
    if(rc != 1) {
        std::cerr << "EVP_DigestSignInit failed" << std::endl;
        std::exit(1);
    }
        
    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if(rc != 1) {
        std::cerr << "EVP_DigestSignUpdate failed" << std::endl;
        std::exit(1);
    }
        
    size_t req = 0;
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if(rc != 1) {
        std::cerr << "EVP_DigestSignFinal failed (1)" << std::endl;
		std::exit(1);
    }
        
    if(!(req > 0)) {
        std::cerr << "EVP_DigestSignFinal failed (2)" << std::endl;
		std::exit(1);
    }
    *sig = (uint8_t*) OPENSSL_malloc(req);
    if(*sig == NULL) {
        std::cerr << "OPENSSL_malloc failed" << std::endl;
        std::exit(1);
    }
    
    rc = EVP_DigestSignFinal(ctx, *sig, &req);
	*slen = req;
    if(rc != 1) {
        std::cerr << "EVP_DigestSignFinal failed (3), return code " << rc << std::endl;
        std::exit(1);
    }
        
    if(rc != 1) {
        std::cerr << "EVP_DigestSignFinal failed, mismatched signature sizes " << req << ", " << *slen << std::endl;
        std::exit(1);
    }
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
}

int32_t read_test_options(int32_t* argcp, char*** argvp, uint32_t* nvals, std::string* address, uint16_t* port) {

	uint32_t int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = {
			{ (void*) nvals, T_NUM, "n", "Number of parallel operation elements, required", true, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7767", false, false }};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	uint32_t nvals = 1;
    uint32_t rsa_len = 2048; //hard_coded currently only
	uint16_t port = 7767;
	std::string address = "127.0.0.1";

	read_test_options(&argc, &argv, &nvals, &address, &port);

    crypto* crypt = new crypto(AES_BITS, (uint8_t*) const_seed);

	uint32_t slen = rsa_len / 8;
    //save the incoming message here
    uint8_t* msg = new uint8_t[AES_BYTES * (nvals + 3)];

    //load the signature into the memory
    BIO* bo;
	bo = BIO_new(BIO_s_mem());
	BIO_write(bo, TEST_SIGNING_KEY, strlen(TEST_SIGNING_KEY));
	EVP_PKEY* sk = PEM_read_bio_PrivateKey(bo, NULL, NULL, NULL);
	BIO_free(bo);

    //receive order: input_a, key, random counter, binding_plaintext
    std::unique_ptr<CSocket> connection = Listen(address, port);
	connection->Receive(msg, AES_BYTES * (nvals + 3));
    uint8_t* input_a = msg;
    uint8_t* key = msg + AES_BYTES * nvals;
    uint8_t* random_counter = msg + AES_BYTES * (nvals + 1);
    uint8_t* binding_plaintext = msg + AES_BYTES * (nvals + 2);

    //AES counter mode: 120 bit nounce, 8 bit counter from random_counter
    uint8_t* random_plaintext = new uint8_t[AES_BYTES * nvals];
	for(uint32_t i = 0; i < nvals; i++) {
		random_plaintext[AES_BYTES * i] = random_counter[0] + i;
		for(uint32_t j = 1; j < AES_BYTES; j++) {
			random_plaintext[AES_BYTES * i + j] = random_counter[j];
		}
	}

    //combine all to be signed values into one block
    uint8_t* sign_values = new uint8_t[AES_BYTES * (nvals + 3)];

    //expand the key for encryptions and compute the ciphertext and the committed ciphertext
    uint8_t* expanded_key = new uint8_t[AES_EXP_KEY_BYTES];
	ExpandKey(expanded_key, key);
    //Save some memory since the ciphertext is placed there later anyways
    uint8_t* ciphertext = sign_values;
	verify_AES_encryption(random_plaintext, expanded_key, nvals, ciphertext, crypt);
    for(uint32_t i = 0; i < AES_BYTES * nvals; i++) {
        ciphertext[i] ^= input_a[i];
    }
    //Save some memory since the committed_ciphertext is placed there later anyways
    uint8_t* committed_ciphertext = sign_values + AES_BYTES * (nvals + 1);
	verify_AES_encryption(binding_plaintext, expanded_key, 1,
	    committed_ciphertext, crypt);

    for(uint32_t i = 0; i < AES_BYTES; i++) {
        sign_values[nvals * AES_BYTES + i] = random_counter[i];
    }
    for(uint32_t i = 0; i < AES_BYTES; i++) {
        sign_values[(nvals + 2) * AES_BYTES + i] = binding_plaintext[i];
    }
    uint8_t *sig = NULL;

    //compute the signature from the data
	rsa_sign(sk, &sig, &slen, sign_values, AES_BYTES * (nvals + 3));

    //send signature
	connection->Send(sig, slen);
    connection->Close();

    delete msg;
    delete random_plaintext;
    delete sign_values;
    delete expanded_key;
    free(sig);
    delete crypt;

	return 0;
}

