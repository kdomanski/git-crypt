/*
 * Copyright 2014 Andrew Ayer
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

#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <windows.h>
#include <vector>
#include <cstring>

std::string System_error::message () const
{
	std::string	mesg(action);
	if (!target.empty()) {
		mesg += ": ";
		mesg += target;
	}
	if (error) {
		LPTSTR	error_message;
		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<LPTSTR>(&error_message),
			0,
			nullptr);
		mesg += error_message;
		LocalFree(error_message);
	}
	return mesg;
}

int exit_status (int status)
{
	return status;
}

void	touch_file (const std::string& filename)
{
	HANDLE	fh = CreateFileA(filename.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (fh == INVALID_HANDLE_VALUE) {
		DWORD	error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND) {
			return;
		} else {
			throw System_error("CreateFileA", filename, error);
		}
	}
	SYSTEMTIME	system_time;
	GetSystemTime(&system_time);
	FILETIME	file_time;
	SystemTimeToFileTime(&system_time, &file_time);

	if (!SetFileTime(fh, nullptr, nullptr, &file_time)) {
		DWORD	error = GetLastError();
		CloseHandle(fh);
		throw System_error("SetFileTime", filename, error);
	}
	CloseHandle(fh);
}

static void	init_std_streams_platform ()
{
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
}

void create_protected_file (const char* path) // TODO
{
}

int util_rename (const char* from, const char* to)
{
	// On Windows OS, it is necessary to ensure target file doesn't exist
	unlink(to);
	return rename(from, to);
}
