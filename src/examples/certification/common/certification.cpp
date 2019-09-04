/**
 \file 		certification.cpp
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
 \brief		Implementation of the certification paper
 */
#include "certification.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/sndthread.h>
#include <ENCRYPTO_utils/rcvthread.h>
#include <ENCRYPTO_utils/connection.h>
#include <ENCRYPTO_utils/socket.h>
#include <ENCRYPTO_utils/channel.h>
#include <ENCRYPTO_utils/timer.h>
#include <openssl/pem.h>
#include <memory>
#include <cstring>

int32_t test_certification(e_role role, const std::string& address, uint16_t port, const std::string& certaddress,
		uint16_t certport, seclvl seclvl, uint32_t nvals, uint32_t nthreads, bool verbose) {

	///////////////////////////////////////////////////////////
	//TEST ONLY; DON'T INIT ON BOTH SERVER AND CLIENT IN A REAL APPLICATION

	crypto* crypt_test = new crypto(seclvl.symbits, (uint8_t*) const_seed);
	//other ifcbits security parameters are currently ignored
	seclvl.ifcbits = 2048;

	//Init the input of the party who desires the inputs to be certified
	CBitVector input_a_test, commit_key_test, sfe_key_test, random_counter_test;
	input_a_test.CreateBytes(AES_BYTES * nvals, crypt_test);
	commit_key_test.CreateBytes(AES_BYTES, crypt_test);
	//Random counter for AES counter mode
	random_counter_test.CreateBytes(AES_BYTES, crypt_test);
	//Change the sfe_key value to check if verification fails if
	//sfe_key does not match the key signed previously
	sfe_key_test.Copy(commit_key_test);
	//sfe_key_test.CreateBytes(AES_BYTES, crypt_test);

	//Init the binding key
	CBitVector binding_key_test;
	binding_key_test.CreateBytes(AES_BYTES, crypt_test);

	//Compute the committed ciphertext from the values defined previously
	//Using AES and the Matyas–Meyer–Oseas construction (with letting the key unchanged)
	//for printing at the bottom of the program
	CBitVector committed_ciphertext_test, expanded_binding_key_test;
	committed_ciphertext_test.CreateBytes(AES_BYTES);
	expanded_binding_key_test.CreateBytes(AES_EXP_KEY_BYTES);
	ExpandKey(expanded_binding_key_test.GetArr(), binding_key_test.GetArr());
	verify_AES_encryption(commit_key_test.GetArr(), expanded_binding_key_test.GetArr(), 1,
			committed_ciphertext_test.GetArr(), crypt_test);
	committed_ciphertext_test.XOR(&commit_key_test);

	//Init the input of the SERVER which does not have certified inputs
	CBitVector input_b_test;
	input_b_test.CreateBytes(AES_BYTES * nvals, crypt_test);

	//Init the test data for the SFE at the bottom of the program
	CBitVector verify_test;
	uint8_t verify_accept_test;
	verify_test.CreateBytes(AES_BYTES * nvals);
	if(sfe_key_test.IsEqual(commit_key_test, 0, AES_BITS)) {

		//////////////////////////////////////
		// actual computation of the test data of the function f starts
		// here with input_a and input_b being the inputs

		verify_test.Copy(input_a_test);
		verify_test.XOR(&input_b_test);

		// function f end here with verify and verify_accept being the data test output
		//////////////////////////////////////

		verify_accept_test = 1;
	} else {
		verify_accept_test = 0;
	}

	delete crypt_test;
	//END TEST VALUES
	/////////////////////////////////////////////////////

	crypto* crypt = new crypto(seclvl.symbits, (uint8_t*) const_seed);

	//the actual input to be certified and used in SFE
	uint8_t* input_a = new uint8_t[AES_BYTES * nvals]; //Evaluator input to be certified
	//the key inputted in the SFE computation
	uint8_t* sfe_key = new uint8_t[AES_BYTES];
	//the key used for the signature data 
	uint8_t* commit_key = new uint8_t[AES_BYTES];

	uint8_t* input_b = new uint8_t[AES_BYTES * nvals]; //Garbler input

	//read the (currently hardcoded) publiv verification key
	BIO* bo = BIO_new(BIO_s_mem());
	BIO_write(bo, TEST_VERIFICATION_KEY, strlen(TEST_VERIFICATION_KEY));
	EVP_PKEY *vk = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
	BIO_free(bo);
	//values to be verified by the digital signature
	//sign_values: [ciphertext, random_counter, committed_ciphertext, binding_key]
	uint8_t* sign_values = new uint8_t[AES_BYTES * (nvals + 3)];
	//value length of the values to be verified by the digital signature
	uint32_t slen = seclvl.ifcbits / 8;
	//the values to be verified including the signature
	uint8_t *msg = new uint8_t[AES_BYTES * (nvals + 2) + slen];
	//the initial counter for AES Counter Mode
	uint8_t *random_counter = new uint8_t[AES_BYTES];
	//The key after the AES key schedule algorithm has been used
	uint8_t *expanded_commit_key = new uint8_t[AES_EXP_KEY_BITS];
	//the to be computed or received ciphertext of the encryption
	uint8_t *ciphertext;
	//the to be computed or received committted ciphertext such
	//that Enc_key(binding_plaintext) = committed_ciphertext
	uint8_t *committed_ciphertext;
	//the ciphertext for AES Counter Mode computed from random_counter
	uint8_t *random_plaintext;

	//Get the desired values; change the inputs if desired
	if(role == CLIENT) {
		//Set the input of the CLIENT Alice here
		memcpy(input_a, input_a_test.GetArr(), AES_BYTES * nvals);
	} else { // role == SERVER
		//Set the input of the SERVER Bob here
		memcpy(input_b, input_b_test.GetArr(), AES_BYTES * nvals);
	}

	timespec total_time_start;
	timespec total_time_end;

	//keeps track of the communication during the signature generation and sending
	uint64_t signing_count = 0;

	clock_gettime(CLOCK_MONOTONIC, &total_time_start);

	//agree to a random plaintext which binds the key
	//TODO consider implementing real commit agreement protocol
	uint8_t* binding_key = new uint8_t[AES_BYTES];
	memcpy(binding_key, binding_key_test.GetArr(), AES_BYTES); //For testing

	//The binding key after the AES key schedule algorithm has been used
	uint8_t *expanded_binding_key = new uint8_t[AES_EXP_KEY_BITS];
	ExpandKey(expanded_binding_key, binding_key);

	uint8_t* cert_msg = new uint8_t[AES_BYTES * 2 + slen];
	
	if(role == CLIENT) {
		//Send the certificate authority the binding key
		std::unique_ptr<CSocket> certconnection = Connect(certaddress, certport);
		certconnection->Send(binding_key, AES_BYTES);

		//Receive the message = commit_key, random_counter, sig
		certconnection->Receive(cert_msg, AES_BYTES * 2 + slen);

		signing_count += certconnection->getRcvCnt() + certconnection->getSndCnt();

		commit_key = cert_msg;
		random_counter = cert_msg + AES_BYTES;
		//Save copies: Use memory which is supposed to
		//be at that memory location anyways
		uint8_t* sig = cert_msg + AES_BYTES * 2;

		random_plaintext = new uint8_t[AES_BYTES * nvals];
		for(uint32_t i = 0; i < nvals; ++i) {
			random_plaintext[AES_BYTES * i] = random_counter[0] + i;
			for(uint32_t j = 1; j < AES_BYTES; ++j) {
				random_plaintext[AES_BYTES * i + j] = random_counter[j];
			}
		}

		//Compute the message which is sent to the party who doesn't have
		//certified inputs
		//Save copies: Use memory which is supposed to
		//be at that memory location later anyways
		ciphertext = msg;
		//ciphertext = new uint8_t[AES_BYTES * nvals];
		//Save copies: Use memory which is supposed to
		//be at that memory location later anyways
		committed_ciphertext = msg + AES_BYTES * (nvals + 1);
		//committed_ciphertext = new uint8_t[AES_BYTES];
		ExpandKey(expanded_commit_key, commit_key);
		verify_AES_encryption(random_plaintext, expanded_commit_key, nvals, ciphertext, crypt);
		for(uint32_t i = 0; i < AES_BYTES * nvals; i++) {
			ciphertext[i] ^= input_a[i];
		}
		//Use Matyas–Meyer–Oseas (without chaning the commit_key) with AES to commit the commit_key
		verify_AES_encryption(commit_key, expanded_binding_key, 1, committed_ciphertext, crypt);
		for(uint32_t i = 0; i < AES_BYTES; ++i) {
			committed_ciphertext[i] ^= commit_key[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; ++i) {
        	msg[nvals * AES_BYTES + i] = random_counter[i];
    	}
		for(uint32_t i = 0; i < slen; ++i) {
        	msg[(nvals + 2) * AES_BYTES + i] = sig[i];
    	}

		//test correct encryption
		uint8_t* input_a_check = new uint8_t[AES_BYTES * nvals];
		uint8_t* decrypt = new uint8_t[AES_BYTES * nvals];
		verify_AES_encryption(random_plaintext, expanded_commit_key, nvals, decrypt, crypt);
		for(uint32_t i = 0; i < AES_BYTES * nvals; ++i) {
			input_a_check[i] = decrypt[i] ^ ciphertext[i];
			if(input_a_check[i] != input_a[i]) {
				std::cerr << "The check of decryption failed" << std::endl;
				std::exit(1);
			}
		}
		delete input_a_check;
		delete decrypt;

		//test correct commitment computation
		uint8_t* committed_ciphertext_check = new uint8_t[AES_BYTES];
		uint8_t* committed_ciphertext_decrypt = new uint8_t[AES_BYTES];
		verify_AES_encryption(commit_key, expanded_binding_key, 1, committed_ciphertext_decrypt, crypt);
		for(uint32_t i = 0; i < AES_BYTES; ++i) {
			committed_ciphertext_check[i] = committed_ciphertext_decrypt[i] ^ commit_key[i];
			if(committed_ciphertext_check[i] != committed_ciphertext[i]) {
				std::cerr << "The check of decryption failed" << std::endl;
				std::exit(1);
			}
		}
		delete committed_ciphertext_check;
		delete committed_ciphertext_decrypt;

		//read the (currently hardcoded) publiv verification key
		bo = BIO_new(BIO_s_mem());
		BIO_write(bo, TEST_VERIFICATION_KEY, strlen(TEST_VERIFICATION_KEY));
		EVP_PKEY *vk = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
		BIO_free(bo);
		
		for(uint32_t i = 0; i < AES_BYTES * nvals; ++i) {
			sign_values[i] = ciphertext[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; ++i) {
			sign_values[AES_BYTES * nvals + i] = random_counter[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; ++i) {
			sign_values[AES_BYTES * (nvals + 1) + i] = committed_ciphertext[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; i++) {
			sign_values[AES_BYTES * (nvals + 2) + i] = binding_key[i];
		}
		rsa_verify(vk, sig, slen, sign_values, AES_BYTES * (nvals + 3));
		//send to SERVER: ciphertext, random_counter, committed_ciphertext, sig
		std::unique_ptr<CSocket> connection = Listen(address, port + 1);
		connection->Send(msg, AES_BYTES * (nvals + 2) + slen);

		signing_count += connection->getRcvCnt() + connection->getSndCnt();
	} else { //role == SERVER

		//Receive the signature and the signature data and
		//check if the data can be verified correctly
		std::unique_ptr<CSocket> connection = Connect(address, port + 1);
		connection->Receive(msg, AES_BYTES * (nvals + 2) + slen);

		signing_count += connection->getRcvCnt() + connection->getSndCnt();

		for(uint32_t i = 0; i < AES_BYTES * (nvals + 2); i++) {
			sign_values[i] = msg[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; i++) {
			sign_values[AES_BYTES * (nvals + 2) + i] = binding_key[i];
		}
		//Save copies: Use memory which is supposed to
		//be at that memory location anyways
		uint8_t* sig = msg + AES_BYTES * (nvals + 2);
		
		//sign_values: [ciphertext, random_counter, committed_ciphertext, binding_key]
		rsa_verify(vk, sig, slen, sign_values, AES_BYTES * (nvals + 3));

		//precompute the public values ciphertext, committed_ciphertext and random_plaintext for the SFE
		ciphertext = msg;
		uint8_t* tmp_random_counter = msg + AES_BYTES * nvals;
		committed_ciphertext = msg + AES_BYTES * (nvals + 1);
		random_plaintext = new uint8_t[AES_BYTES * nvals];
		for(uint32_t i = 0; i < nvals; i++) {
			random_plaintext[AES_BYTES * i] = tmp_random_counter[0] + i;
			for(uint32_t j = 1; j < AES_BYTES; j++) {
				random_plaintext[AES_BYTES * i + j] = tmp_random_counter[j];
			}
		}
	}

	//Set sfe key here in case you want to check behavior if sfe key and commited key differ
	if(role == CLIENT) {
		memcpy(sfe_key, sfe_key_test.GetArr(), AES_BYTES); //test only
		//memcpy(sfe_key, commit_key, AES_BYTES); //real application
	}

	//Setup the ABY Framework
	ABYParty* party = new ABYParty(role, address, port, seclvl, 32, nthreads, MT_OT, 4000000);
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* circ = sharings[S_YAO]->GetCircuitBuildRoutine();

	//client key to compute certified inputs
	share *s_key;
	if(role == CLIENT) {
		s_key = circ->PutINGate(sfe_key, AES_KEY_BITS, CLIENT);
	} else {
		s_key = circ->PutDummyINGate(AES_KEY_BITS);
	}

	//server input without certification
	share *s_b;
	if(role == SERVER) {
		s_b = circ->PutSIMDINGate(nvals, input_b, AES_BITS, SERVER);
	} else {
		s_b = circ->PutDummySIMDINGate(nvals, AES_BITS);
	}

	//public inputs
	//These inputs seem strange, but since semi-honest garblers are assumed anyways this is fine for now
	share *s_random_plaintext = circ->PutSIMDINGate(nvals, random_plaintext, AES_KEY_BITS, SERVER); //TODO Change to a constant gate
	share *s_ciphertext = circ->PutSIMDINGate(nvals, ciphertext, AES_BITS, SERVER); //TODO Change to a constant gate
	share *s_binding_key = circ->PutINGate(binding_key, AES_BITS, SERVER); //TODO Change to a constant gate
	share *s_committed_ciphertext = circ->PutINGate(committed_ciphertext, AES_BITS, SERVER); //TODO Change to a constant gate

	//Input calculation of the party having certified inputs
	share *s_key_expanded = BuildKeyExpansion(s_key, (BooleanCircuit*) circ, false);
	share *s_key_repeated = circ->PutRepeaterGate(nvals,s_key_expanded);
	share *s_a = circ->PutXORGate(s_ciphertext, BuildAESCircuit(s_random_plaintext, s_key_repeated, (BooleanCircuit*) circ, false));

	//Check if the inputed key matches the committment
	share *s_binding_key_expanded = BuildKeyExpansion(s_binding_key, (BooleanCircuit*) circ, false);
	share *s_aes_ciphertext = BuildAESCircuit(s_key, s_binding_key_expanded, (BooleanCircuit*) circ, false);
	share *s_check_ciphertext = circ->PutXORGate(s_aes_ciphertext, s_key);

	share *s_accept = circ->PutEQGate(s_committed_ciphertext, s_check_ciphertext);

	//////////////////////////////////////
	// actual computation of the function f starts here with s_a and s_b being the inputs

	share *s_res_comp = circ->PutGTGate(s_a, s_b);

	// actual computation of the function f ends here with s_res_comp being the actual computation output
	//////////////////////////////////////

	//Mask the actual computation with the accept value so that values do not get leaked if
	//the key does not match the key committed previously
	//TODO simplify this three lines,
	//intention is that the single bit gets expanded to AES_BITS bits of 1 nvals times
	share *s_accept_repeated = circ->PutRepeaterGate(AES_BITS, s_accept);
	s_accept_repeated = circ->PutSplitterGate(s_accept_repeated);
	s_accept_repeated = circ->PutRepeaterGate(nvals, s_accept_repeated);
	//end TODO
	share *s_res = circ->PutANDGate(s_res_comp, s_accept_repeated);
	share *s_out = circ->PutOUTGate(s_res, ALL);
	share *s_accept_out = circ->PutOUTGate(s_accept, ALL);

	party->ExecCircuit();
	
	//Read the output values from the SFE computation
	uint8_t* output = s_out->get_clear_value_ptr();
	CBitVector out(nvals * AES_BITS);
	uint8_t accept = s_accept_out->get_clear_value<uint8_t>();
	out.SetBytes(output, 0L, (uint64_t) AES_BYTES * nvals);

	//Print Results of the computation, test the results, print benchmark results
#ifndef BATCH
	///////////////////////////////////////////////////////////
	//TEST ONLY; DON'T USE THIS IN A REAL APPLICATION
	if(!verbose) {
		std::cout << "Key:\t";
		commit_key_test.PrintHex(0, AES_BYTES);
		std::cout << "Inputted Key into SFE:\t";
		sfe_key_test.PrintHex(0, AES_BYTES);
		std::cout << "Binding Key:\t";
		binding_key_test.PrintHex(0, AES_BYTES);
		std::cout << "Committed ciphertext:\t";
		committed_ciphertext_test.PrintHex(0, AES_BYTES);
		std::cout << "Plaintext Initialization counter:\t";
		random_counter_test.PrintHex(0, AES_BYTES);
		std::cout << "Accept output of SFE:\t" << ((int) accept) << std::endl;

		for (uint32_t i = 0; i < nvals; i++) {
			std::cout << "(" << i << ") Input a:\t";
			input_a_test.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
			std::cout << "(" << i << ") Input b:\t";
			input_b_test.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
			std::cout << "(" << i << ") Circ:\t";
			out.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
			std::cout << "(" << i << ") Verify:\t";
			verify_test.PrintHex(i * AES_BYTES, (i + 1) * AES_BYTES);
		}
	}
	assert(accept == verify_accept_test);
	if(accept == verify_accept_test) {
		assert(verify_test.IsEqual(out));
	} else {
		//TODO routine for case
	}
	if(!verbose) {
		std::cout << "all tests succeeded" << std::endl;
	}
	//END TESTS
	/////////////////////////////////////////////////////
#else

	clock_gettime(CLOCK_MONOTONIC, &total_time_end);

	double certification_time = getMillies(total_time_start, total_time_end);
	uint64_t total_communication = signing_count + party->GetSentData() + party->GetReceivedData();
	std::cout << certification_time << "\t" << (certification_time - party->GetTiming(P_BASE_OT)) << "\t" << total_communication << std::endl;

#endif

	delete input_a;
	delete sfe_key;
	delete input_b;
	delete msg;
	delete sign_values;
	delete random_plaintext;
	delete expanded_commit_key;
	delete expanded_binding_key;
	delete cert_msg;
	delete crypt;
	delete party;
	free(output);
	return 0;
}

void rsa_verify(EVP_PKEY* vkey, const uint8_t* sig, uint32_t slen, const uint8_t* msg, uint32_t mlen) {
    
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
        
    rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, vkey);
    if(rc != 1) {
        std::cerr << "EVP_DigestVerifyInit failed" << std::endl;
        std::exit(1);
    }
        
    rc = EVP_DigestSignUpdate(ctx, msg, mlen);
    if(rc != 1) {
        std::cerr << "EVP_DigestVerifyUpdate failed" << std::endl;
        std::exit(1);
    }

    rc = EVP_DigestVerifyFinal(ctx, sig, slen);
    if(rc != 1) {
        std::cerr << "EVP_DigestVerifyFinal failed" << std::endl;
		std::exit(1);
    }
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
}

