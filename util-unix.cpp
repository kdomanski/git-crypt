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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <errno.h>
#include <utime.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstddef>
#include <algorithm>

std::string System_error::message () const
{
	std::string	mesg(action);
	if (!target.empty()) {
		mesg += ": ";
		mesg += target;
	}
	if (error) {
		mesg += ": ";
		mesg += strerror(error);
	}
	return mesg;
}

int	exit_status (int wait_status)
{
	return wait_status != -1 && WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : -1;
}

void	touch_file (const std::string& filename)
{
	if (utimes(filename.c_str(), nullptr) == -1 && errno != ENOENT) {
		throw System_error("utimes", filename, errno);
	}
}

static void	init_std_streams_platform ()
{
}

void	create_protected_file (const char* path)
{
	int	fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (fd == -1) {
		throw System_error("open", path, errno);
	}
	close(fd);
}

int util_rename (const char* from, const char* to)
{
	return rename(from, to);
}

