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

#include <openssl/opensslconf.h>

#if defined(OPENSSL_API_COMPAT)

#include "crypto.hpp"
#include "key.hpp"
#include "util.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sstream>
#include <cstring>

void init_crypto ()
{
	ERR_load_crypto_strings();
}

void random_bytes (unsigned char* buffer, size_t len)
{
	if (RAND_bytes(buffer, len) != 1) {
		std::ostringstream	message;
		while (unsigned long code = ERR_get_error()) {
			char		error_string[120];
			ERR_error_string_n(code, error_string, sizeof(error_string));
			message << "OpenSSL Error: " << error_string << "; ";
		}
		throw Crypto_error("random_bytes", message.str());
	}
}

#endif
