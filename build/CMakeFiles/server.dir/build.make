# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build

# Include any dependencies generated for this target.
include CMakeFiles/server.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/server.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/server.dir/flags.make

CMakeFiles/server.dir/server/server.cpp.o: CMakeFiles/server.dir/flags.make
CMakeFiles/server.dir/server/server.cpp.o: ../server/server.cpp
CMakeFiles/server.dir/server/server.cpp.o: CMakeFiles/server.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/server.dir/server/server.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/server.dir/server/server.cpp.o -MF CMakeFiles/server.dir/server/server.cpp.o.d -o CMakeFiles/server.dir/server/server.cpp.o -c /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/server/server.cpp

CMakeFiles/server.dir/server/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/server.dir/server/server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/server/server.cpp > CMakeFiles/server.dir/server/server.cpp.i

CMakeFiles/server.dir/server/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/server.dir/server/server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/server/server.cpp -o CMakeFiles/server.dir/server/server.cpp.s

# Object files for target server
server_OBJECTS = \
"CMakeFiles/server.dir/server/server.cpp.o"

# External object files for target server
server_EXTERNAL_OBJECTS =

server: CMakeFiles/server.dir/server/server.cpp.o
server: CMakeFiles/server.dir/build.make
server: CMakeFiles/server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/server.dir/build: server
.PHONY : CMakeFiles/server.dir/build

CMakeFiles/server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/server.dir/clean

CMakeFiles/server.dir/depend:
	cd /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build /home/divyanshu/Atlassian_P/secure_file_transfer_with_chat_cpp/build/CMakeFiles/server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/server.dir/depend

