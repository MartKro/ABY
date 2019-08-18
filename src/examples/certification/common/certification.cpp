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
	//Change the sfe_key value to check if verification fails if
	//sfe_key does not match the key signed previously
	sfe_key_test.Copy(commit_key_test);
	//sfe_key.CreateBytes(AES_BYTES, crypt);
	//Random counter for AES counter mode
	random_counter_test.CreateBytes(AES_BYTES, crypt_test);

	//Init the input of the other party
	CBitVector input_b_test;
	input_b_test.CreateBytes(AES_BYTES * nvals, crypt_test);

	//Init the binding plaintext
	CBitVector binding_plaintext_test;
	binding_plaintext_test.CreateBytes(AES_BYTES, crypt_test);

	//Compute the committed ciphertext from the values defined previously
	//for printing at the bottom of the program
	CBitVector committed_ciphertext_test, expanded_commit_key_test;
	committed_ciphertext_test.CreateBytes(AES_BYTES);
	expanded_commit_key_test.CreateBytes(AES_EXP_KEY_BITS);
	verify_AES_encryption(binding_plaintext_test.GetArr(), expanded_commit_key_test.GetArr(), 1,
			committed_ciphertext_test.GetArr(), crypt_test);

	//Init the test data for the SFE at the bottom of the program
	CBitVector verify_test;
	uint8_t verify_accept_test;
	verify_test.CreateBytes(AES_BYTES * nvals);
	if(sfe_key_test.IsEqual(commit_key_test, 0, AES_BITS)) {

		//////////////////////////////////////
		// actual computation of the test data of the function f starts
		// here with input_a and input_b being the inputs

		verify_test.Copy(input_a_test);
		verify_test.XORVector(input_b_test, 0, AES_BYTES * nvals);

		// function f end here with verify and verify_accept being the data test output
		//////////////////////////////////////

		verify_accept_test = 1;
	} else {
		verify_accept_test = 0;
	}
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

	//Get the desired values
	if(role == CLIENT) {
		memcpy(input_a, input_a_test.GetArr(), AES_BYTES * nvals);
		memcpy(sfe_key, sfe_key_test.GetArr(), AES_BYTES);
		memcpy(commit_key, commit_key_test.GetArr(), AES_BYTES);
		memcpy(random_counter, random_counter_test.GetArr(), AES_BYTES);
	} else { // role == SERVER
		memcpy(input_b, input_b_test.GetArr(), AES_BYTES * nvals);
	}

	timespec digital_signature_certification_start;
	timespec digital_signature_certification_end;
	timespec digital_signature_vertification_start;
	timespec digital_signature_vertification_end;
	timespec precomputation_start;
	timespec precomputation_end;

	clock_gettime(CLOCK_MONOTONIC, &digital_signature_certification_start);
	clock_gettime(CLOCK_MONOTONIC, &digital_signature_vertification_start);

	//agree to a random plaintext which binds the key
	//consider better agreement protocol
	uint8_t* binding_plaintext = new uint8_t[AES_BYTES];
	memcpy(binding_plaintext, binding_plaintext_test.GetArr(), AES_BYTES);
	
	if(role == CLIENT) {
		//Send the certificate authority the
		//values needed to compute the signature from it
		uint8_t* sig_calc_values = new uint8_t[AES_BYTES * (nvals + 3)];
		random_plaintext = new uint8_t[AES_BYTES * nvals];
		for(uint32_t i = 0; i < nvals; i++) {
			random_plaintext[AES_BYTES * i] = random_counter[0] + i;
			for(uint32_t j = 1; j < AES_BYTES; j++) {
				random_plaintext[AES_BYTES * i + j] = random_counter[j];
			}
		}
		for(uint32_t i = 0; i < AES_BYTES * nvals; i++) {
        	sig_calc_values[i] = input_a[i];
    	}
    	for(uint32_t i = 0; i < AES_BYTES; i++) {
        	sig_calc_values[nvals * AES_BYTES + i] = commit_key[i];
    	}
    	for(uint32_t i = 0; i < AES_BYTES; i++) {
        	sig_calc_values[(nvals + 1) * AES_BYTES + i] = random_counter[i];
    	}
    	for(uint32_t i = 0; i < AES_BYTES; i++) {
        	sig_calc_values[(nvals + 2) * AES_BYTES + i] = binding_plaintext[i];
    	}
		std::unique_ptr<CSocket> certconnection = Connect(certaddress, certport);
		//send order: input_a, commit_key, random counter, binding_plaintext
		certconnection->Send(sig_calc_values, AES_BYTES * (nvals + 3));
		delete sig_calc_values;

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
		verify_AES_encryption(binding_plaintext, expanded_commit_key, 1, committed_ciphertext, crypt);

		//Receive the signature, check if the data can be verified correctly
		//and send the values to the party without certified inputs
		//such that the other party can check the too
		//Save copies: Use memory which is supposed to
		//be at that memory location later anyways
		uint8_t *sig = msg + AES_BYTES * (nvals + 2);
		certconnection->Receive(sig, slen);

		clock_gettime(CLOCK_MONOTONIC, &digital_signature_certification_end);

		//read the (currently hardcoded) publiv verification key
		bo = BIO_new(BIO_s_mem());
		BIO_write(bo, TEST_VERIFICATION_KEY, strlen(TEST_VERIFICATION_KEY));
		EVP_PKEY *vk = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
		BIO_free(bo);
		for(uint32_t i = 0; i < AES_BYTES; i++) {
        	msg[nvals * AES_BYTES + i] = random_counter[i];
    	}
		for(uint32_t i = 0; i < AES_BYTES * (nvals + 2); i++) {
			sign_values[i] = msg[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; i++) {
			sign_values[AES_BYTES * (nvals + 2) + i] = binding_plaintext[i];
		}
		//sign_values: [ciphertext, random_counter, committed_ciphertext, binding_plaintext]
		rsa_verify(vk, sig, slen, sign_values, AES_BYTES * (nvals + 3));
		//send to SERVER: ciphertext, random_counter, committed_ciphertext, sig
		std::unique_ptr<CSocket> connection = Listen(address, 7768);
		connection->Send(msg, AES_BYTES * (nvals + 2) + slen);

		clock_gettime(CLOCK_MONOTONIC, &digital_signature_vertification_end);
		clock_gettime(CLOCK_MONOTONIC, &precomputation_start);
	} else { //role == SERVER
		clock_gettime(CLOCK_MONOTONIC, &digital_signature_certification_end);

		//Receive the signature and the signature data and
		//check if the data can be verified correctly
		std::unique_ptr<CSocket> connection = Connect(address, 7768);
		connection->Receive(msg, AES_BYTES * (nvals + 2) + slen);
		for(uint32_t i = 0; i < AES_BYTES * (nvals + 2); i++) {
			sign_values[i] = msg[i];
		}
		for(uint32_t i = 0; i < AES_BYTES; i++) {
			sign_values[AES_BYTES * (nvals + 2) + i] = binding_plaintext[i];
		}
		//Save copies: Use memory which is supposed to
		//be at that memory location anyways
		uint8_t* sig = msg + AES_BYTES * (nvals + 2);
		
		//sign_values: [ciphertext, random_counter, committed_ciphertext, binding_plaintext]
		rsa_verify(vk, sig, slen, sign_values, AES_BYTES * (nvals + 3));

		clock_gettime(CLOCK_MONOTONIC, &digital_signature_vertification_end);
		clock_gettime(CLOCK_MONOTONIC, &precomputation_start);

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
	share *s_binding_plaintext = circ->PutINGate(binding_plaintext, AES_BITS, SERVER); //TODO Change to a constant gate
	share *s_committed_ciphertext = circ->PutINGate(committed_ciphertext, AES_BITS, SERVER); //TODO Change to a constant gate

	//Input calculation of the party having certified inputs
	share *s_key_expanded = BuildKeyExpansion(s_key, (BooleanCircuit*) circ, false);
	share *s_key_repeated = circ->PutRepeaterGate(nvals,s_key_expanded);
	share *s_a = circ->PutXORGate(s_ciphertext, BuildAESCircuit(s_random_plaintext, s_key_repeated, (BooleanCircuit*) circ, false));

	//Check if the inputed key matches the committment
	share *s_check_ciphertext = BuildAESCircuit(s_binding_plaintext, s_key_expanded, (BooleanCircuit*) circ, false);
	share *s_accept = circ->PutEQGate(s_committed_ciphertext, s_check_ciphertext);

	//////////////////////////////////////
	// actual computation of the function f starts here with s_a and s_b being the inputs

	share *s_res_comp = circ->PutXORGate(s_a, s_b);

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

	clock_gettime(CLOCK_MONOTONIC, &precomputation_end);

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
		std::cout << "Binding Plaintext:\t";
		binding_plaintext_test.PrintHex(0, AES_BYTES);
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
	long cert1 = (digital_signature_certification_start.tv_sec * 1000000)
			+ (digital_signature_certification_start.tv_nsec / 1000);
	long cert2 = (digital_signature_certification_end.tv_sec * 1000000)
			+ (digital_signature_certification_end.tv_nsec / 1000);

	long certification_time = (double) (cert2 - cert1) / 1000;

	long ver1 = (digital_signature_vertification_start.tv_sec * 1000000)
			+ (digital_signature_vertification_start.tv_nsec / 1000);
	long ver2 = (digital_signature_vertification_end.tv_sec * 1000000)
			+ (digital_signature_vertification_end.tv_nsec / 1000);

	long verification_time = (double) (ver2 - ver1) / 1000;

	long pretime1 = (precomputation_start.tv_sec * 1000000) + (precomputation_start.tv_nsec / 1000);
	long pretime2 = (precomputation_end.tv_sec * 1000000) + (precomputation_end.tv_nsec / 1000);

	long precomputation_time = (double) (pretime2 - pretime1) / 1000;

	std::cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_GARBLE) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) <<
			"\t" << party->GetSentData(P_TOTAL) + party->GetReceivedData(P_TOTAL) << "\t";
	std::cout << sharings[S_YAO]->GetNumNonLinearOperations()	<< "\t" << sharings[S_YAO]->GetMaxCommunicationRounds() << "\t";
	std::cout << certification_time << "\t" << verification_time << "\t" <<  precomputation_time << std::endl;
#endif

	delete input_a;
	delete sfe_key;
	delete commit_key;
	delete random_counter;
	delete input_b;
	delete msg;
	delete sign_values;
	delete random_plaintext;
	delete expanded_commit_key;
	delete crypt_test;
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

/*
share* PutSIMDConsGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) {
	share* res;
	for(uint32_t i = 1; i < nvals; i++) {
		//TODO replace to (see bug #X)
		//s_random_plaintext_reading = circ->PutCONSGate(random_plaintext + i * AES_BYTES, AES_BYTES);
		//TODO remove if bug #X is fixed
		std::vector<uint32_t> gateids(AES_BITS);
		for(uint32_t j = 0; j < AES_BYTES; j++) {
			std::vector<uint32_t> one_gate = circ->PutCONSGate(random_plaintext[i * AES_BYTES + j])->get_wires();
			gateids.insert(std::end(gateids), std::begin(one_gate), std::end(one_gate));
		}
		s_random_plaintext = PutCombinerGate(s_random_plaintext, new boolshare(gateids, circ));
		//end TODO
	}
}
*/
