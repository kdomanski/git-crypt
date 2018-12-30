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
#include "util.hpp"
#include "coprocess.hpp"
#include <string>
#include <iostream>

int exec_command (const std::vector<std::string>& args)
{
	Coprocess	proc;
	proc.spawn(args);
	return proc.wait();
}

int exec_command (const std::vector<std::string>& args, std::ostream& output)
{
	Coprocess	proc;
	std::istream*	proc_stdout = proc.stdout_pipe();
	proc.spawn(args);
	output << proc_stdout->rdbuf();
	return proc.wait();
}

static void	init_std_streams_platform (); // platform-specific initialization

void		init_std_streams ()
{
	// The following two lines are essential for achieving good performance:
	std::ios_base::sync_with_stdio(false);
	std::cin.tie(0);

	std::cin.exceptions(std::ios_base::badbit);
	std::cout.exceptions(std::ios_base::badbit);

	init_std_streams_platform();
}

#ifdef _WIN32
#include "util-win32.cpp"
#else
#include "util-unix.cpp"
#endif
