/**
 \file 		certification_test.cpp
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
 \brief		Certification Test class implementation.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/certification.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* nvals,
		uint32_t* secparam, std::string* address, uint16_t* port, std::string* certaddress,
		uint16_t* certport, bool* verbose, uint32_t* nthreads) {

	uint32_t int_role = 0, int_port = 0, int_certport = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1, 1 is the party inputting certified inputs", true, false },
			{ (void*) nvals, T_NUM, "n", "Number of parallel operation elements", false, false },
			{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port (and Port + 1), default: 7766", false, false },
			{ (void*) certaddress, T_STR, "b", "IP-address of certification authority, default: localhost", false, false },
			{ (void*) &int_certport, T_NUM, "q", "Port of certification authority, default: 7768", false, false },
			{ (void*) verbose, T_FLAG, "v", "Do not print the result of the evaluation, default: off", false, false },
			{ (void*) nthreads, T_NUM, "t", "Number of threads, default: 1", false, false }};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	if (int_certport != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*certport = (uint16_t) int_certport;
	}

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t nvals = 1, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	std::string certaddress = "127.0.0.1";
	uint16_t certport = 7768;
	bool verbose = false;

	read_test_options(&argc, &argv, &role, &nvals, &secparam, &address, &port, &certaddress,
			&certport, &verbose, &nthreads);

	seclvl seclvl = get_sec_lvl(secparam);

	test_certification(role, address, port, certaddress, certport, seclvl, nvals, nthreads, verbose);

	return 0;
}

