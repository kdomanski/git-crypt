/*
 * Copyright 2012, 2014 Andrew Ayer
 *
 * This file is part of git-crypt.
 *
 * git-crypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * git-crypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with git-crypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#include "git-crypt.hpp"
#include "commands.hpp"
#include "util.hpp"
#include "key.hpp"
#include "gpg.hpp"
#include "parse_options.hpp"
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <string.h>

const char*	argv0;

extern "C"
int cpp_main (int argc, const char** argv)
try {
	argv0 = argv[0];
	--argc;
	++argv;

	/*
	 * General initialization
	 */

	init_std_streams();

	/*
	 * Pass off to command handler
	 */
	const char*		command = argv[0];
	--argc;
	++argv;

	try {
		// Public commands:
		if (std::strcmp(command, "unlock") == 0) {
			return unlock(argc, argv);
		}
		if (std::strcmp(command, "export-key") == 0) {
			return export_key(argc, argv);
		}
		if (std::strcmp(command, "status") == 0) {
			return status(argc, argv);
		}
	} catch (const Option_error& e) {
		std::clog << "git-crypt: Error: " << e.option_name << ": " << e.message << std::endl;
		//help_for_command(command, std::clog);
		return 2;
	}

	std::clog << "Error: '" << command << "' is not a git-crypt command. See 'git-crypt help'." << std::endl;
	return 2;

} catch (const Error& e) {
	std::cerr << "git-crypt: Error: " << e.message << std::endl;
	return 1;
} catch (const Gpg_error& e) {
	std::cerr << "git-crypt: GPG error: " << e.message << std::endl;
	return 1;
} catch (const System_error& e) {
	std::cerr << "git-crypt: System error: " << e.message() << std::endl;
	return 1;
} catch (Key_file::Incompatible) {
	std::cerr << "git-crypt: This repository contains a incompatible key file.  Please upgrade git-crypt." << std::endl;
	return 1;
} catch (Key_file::Malformed) {
	std::cerr << "git-crypt: This repository contains a malformed key file.  It may be corrupted." << std::endl;
	return 1;
} catch (const std::ios_base::failure& e) {
	std::cerr << "git-crypt: I/O error: " << e.what() << std::endl;
	return 1;
}
