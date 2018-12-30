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

#include "commands.hpp"
#include "util.hpp"
#include "parse_options.hpp"
#include "coprocess.hpp"
#include <unistd.h>
#include <stdint.h>
#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstddef>
#include <cstring>
#include <cctype>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <exception>
#include <vector>

static std::string get_path_to_top ()
{
	// git rev-parse --show-cdup
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--show-cdup");

	std::stringstream		output;

	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git rev-parse --show-cdup' failed - is this a Git repository?");
	}

	std::string			path_to_top;
	std::getline(output, path_to_top);

	return path_to_top;
}

// returns filter and diff attributes as a pair
static std::pair<std::string, std::string> get_file_attributes (const std::string& filename)
{
	// git check-attr filter diff -- filename
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("check-attr");
	command.push_back("filter");
	command.push_back("diff");
	command.push_back("--");
	command.push_back(filename);

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git check-attr' failed - is this a Git repository?");
	}

	std::string			filter_attr;
	std::string			diff_attr;

	std::string			line;
	// Example output:
	// filename: filter: git-crypt
	// filename: diff: git-crypt
	while (std::getline(output, line)) {
		// filename might contain ": ", so parse line backwards
		// filename: attr_name: attr_value
		//         ^name_pos  ^value_pos
		const std::string::size_type	value_pos(line.rfind(": "));
		if (value_pos == std::string::npos || value_pos == 0) {
			continue;
		}
		const std::string::size_type	name_pos(line.rfind(": ", value_pos - 1));
		if (name_pos == std::string::npos) {
			continue;
		}

		const std::string		attr_name(line.substr(name_pos + 2, value_pos - (name_pos + 2)));
		const std::string		attr_value(line.substr(value_pos + 2));

		if (attr_value != "unspecified" && attr_value != "unset" && attr_value != "set") {
			if (attr_name == "filter") {
				filter_attr = attr_value;
			} else if (attr_name == "diff") {
				diff_attr = attr_value;
			}
		}
	}

	return std::make_pair(filter_attr, diff_attr);
}

static bool check_if_blob_is_encrypted (const std::string& object_id)
{
	// git cat-file blob object_id

	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("cat-file");
	command.push_back("blob");
	command.push_back(object_id);

	// TODO: do this more efficiently - don't read entire command output into buffer, only read what we need
	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git cat-file' failed - is this a Git repository?");
	}

	char				header[10];
	output.read(header, sizeof(header));
	return output.gcount() == sizeof(header) && std::memcmp(header, "\0GITCRYPT\0", 10) == 0;
}

static bool check_if_file_is_encrypted (const std::string& filename)
{
	// git ls-files -sz filename
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("ls-files");
	command.push_back("-sz");
	command.push_back("--");
	command.push_back(filename);

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git ls-files' failed - is this a Git repository?");
	}

	if (output.peek() == -1) {
		return false;
	}

	std::string			mode;
	std::string			object_id;
	output >> mode >> object_id;

	return check_if_blob_is_encrypted(object_id);
}

static bool is_git_file_mode (const std::string& mode)
{
	return (std::strtoul(mode.c_str(), nullptr, 8) & 0170000) == 0100000;
}

int status (int argc, const char** argv)
{
	// Usage:
	//  git-crypt status -r [-z]			Show repo status
	//  git-crypt status [-e | -u] [-z] [FILE ...]	Show encrypted status of files
	//  git-crypt status -f				Fix unencrypted blobs

	bool		repo_status_only = false;	// -r show repo status only
	bool		show_encrypted_only = false;	// -e show encrypted files only
	bool		show_unencrypted_only = false;	// -u show unencrypted files only
	bool		fix_problems = false;		// -f fix problems
	bool		machine_output = false;		// -z machine-parseable output

	Options_list	options;
	options.push_back(Option_def("-r", &repo_status_only));
	options.push_back(Option_def("-e", &show_encrypted_only));
	options.push_back(Option_def("-u", &show_unencrypted_only));
	options.push_back(Option_def("-f", &fix_problems));
	options.push_back(Option_def("--fix", &fix_problems));
	options.push_back(Option_def("-z", &machine_output));

	int		argi = parse_options(options, argc, argv);

	if (repo_status_only) {
		if (show_encrypted_only || show_unencrypted_only) {
			std::clog << "Error: -e and -u options cannot be used with -r" << std::endl;
			return 2;
		}
		if (fix_problems) {
			std::clog << "Error: -f option cannot be used with -r" << std::endl;
			return 2;
		}
		if (argc - argi != 0) {
			std::clog << "Error: filenames cannot be specified when -r is used" << std::endl;
			return 2;
		}
	}

	if (show_encrypted_only && show_unencrypted_only) {
		std::clog << "Error: -e and -u options are mutually exclusive" << std::endl;
		return 2;
	}

	if (fix_problems && (show_encrypted_only || show_unencrypted_only)) {
		std::clog << "Error: -e and -u options cannot be used with -f" << std::endl;
		return 2;
	}

	if (machine_output) {
		// TODO: implement machine-parseable output
		std::clog << "Sorry, machine-parseable output is not yet implemented" << std::endl;
		return 2;
	}

	if (argc - argi == 0) {
		// TODO: check repo status:
		//	is it set up for git-crypt?
		//	which keys are unlocked?
		//	--> check for filter config (see configure_git_filters()) and corresponding internal key

		if (repo_status_only) {
			return 0;
		}
	}

	// git ls-files -cotsz --exclude-standard ...
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("ls-files");
	command.push_back("-cotsz");
	command.push_back("--exclude-standard");
	command.push_back("--");
	if (argc - argi == 0) {
		const std::string	path_to_top(get_path_to_top());
		if (!path_to_top.empty()) {
			command.push_back(path_to_top);
		}
	} else {
		for (int i = argi; i < argc; ++i) {
			command.push_back(argv[i]);
		}
	}

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git ls-files' failed - is this a Git repository?");
	}

	// Output looks like (w/o newlines):
	// ? .gitignore\0
	// H 100644 06ec22e5ed0de9280731ef000a10f9c3fbc26338 0     afile\0

	std::vector<std::string>	files;
	bool				attribute_errors = false;
	bool				unencrypted_blob_errors = false;
	unsigned int			nbr_of_fixed_blobs = 0;
	unsigned int			nbr_of_fix_errors = 0;

	while (output.peek() != -1) {
		std::string		tag;
		std::string		object_id;
		std::string		filename;
		output >> tag;
		if (tag != "?") {
			std::string	mode;
			std::string	stage;
			output >> mode >> object_id >> stage;
			if (!is_git_file_mode(mode)) {
				continue;
			}
		}
		output >> std::ws;
		std::getline(output, filename, '\0');

		// TODO: get file attributes en masse for efficiency... unfortunately this requires machine-parseable output from git check-attr to be workable, and this is only supported in Git 1.8.5 and above (released 27 Nov 2013)
		const std::pair<std::string, std::string> file_attrs(get_file_attributes(filename));

		if (file_attrs.first == "git-crypt" || std::strncmp(file_attrs.first.c_str(), "git-crypt-", 10) == 0) {
			// File is encrypted
			const bool	blob_is_unencrypted = !object_id.empty() && !check_if_blob_is_encrypted(object_id);

			if (fix_problems && blob_is_unencrypted) {
				if (access(filename.c_str(), F_OK) != 0) {
					std::clog << "Error: " << filename << ": cannot stage encrypted version because not present in working tree - please 'git rm' or 'git checkout' it" << std::endl;
					++nbr_of_fix_errors;
				} else {
					touch_file(filename);
					std::vector<std::string>	git_add_command;
					git_add_command.push_back("git");
					git_add_command.push_back("add");
					git_add_command.push_back("--");
					git_add_command.push_back(filename);
					if (!successful_exit(exec_command(git_add_command))) {
						throw Error("'git-add' failed");
					}
					if (check_if_file_is_encrypted(filename)) {
						std::cout << filename << ": staged encrypted version" << std::endl;
						++nbr_of_fixed_blobs;
					} else {
						std::clog << "Error: " << filename << ": still unencrypted even after staging" << std::endl;
						++nbr_of_fix_errors;
					}
				}
			} else if (!fix_problems && !show_unencrypted_only) {
				// TODO: output the key name used to encrypt this file
				std::cout << "    encrypted: " << filename;
				if (file_attrs.second != file_attrs.first) {
					// but diff filter is not properly set
					std::cout << " *** WARNING: diff=" << file_attrs.first << " attribute not set ***";
					attribute_errors = true;
				}
				if (blob_is_unencrypted) {
					// File not actually encrypted
					std::cout << " *** WARNING: staged/committed version is NOT ENCRYPTED! ***";
					unencrypted_blob_errors = true;
				}
				std::cout << std::endl;
			}
		} else {
			// File not encrypted
			if (!fix_problems && !show_encrypted_only) {
				std::cout << "not encrypted: " << filename << std::endl;
			}
		}
	}

	int				exit_status = 0;

	if (attribute_errors) {
		std::cout << std::endl;
		std::cout << "Warning: one or more files has a git-crypt filter attribute but not a" << std::endl;
		std::cout << "corresponding git-crypt diff attribute.  For proper 'git diff' operation" << std::endl;
		std::cout << "you should fix the .gitattributes file to specify the correct diff attribute." << std::endl;
		std::cout << "Consult the git-crypt documentation for help." << std::endl;
		exit_status = 1;
	}
	if (unencrypted_blob_errors) {
		std::cout << std::endl;
		std::cout << "Warning: one or more files is marked for encryption via .gitattributes but" << std::endl;
		std::cout << "was staged and/or committed before the .gitattributes file was in effect." << std::endl;
		std::cout << "Run 'git-crypt status' with the '-f' option to stage an encrypted version." << std::endl;
		exit_status = 1;
	}
	if (nbr_of_fixed_blobs) {
		std::cout << "Staged " << nbr_of_fixed_blobs << " encrypted file" << (nbr_of_fixed_blobs != 1 ? "s" : "") << "." << std::endl;
		std::cout << "Warning: if these files were previously committed, unencrypted versions still exist in the repository's history." << std::endl;
	}
	if (nbr_of_fix_errors) {
		std::cout << "Unable to stage " << nbr_of_fix_errors << " file" << (nbr_of_fix_errors != 1 ? "s" : "") << "." << std::endl;
		exit_status = 1;
	}

	return exit_status;
}
