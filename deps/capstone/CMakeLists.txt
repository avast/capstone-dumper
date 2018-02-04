include(ExternalProject)

ExternalProject_Add(capstone-project
	GIT_REPOSITORY https://github.com/aquynh/capstone.git
	GIT_TAG next
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DCAPSTONE_BUILD_STATIC=ON
		-DCAPSTONE_BUILD_SHARED=OFF
		-DCAPSTONE_BUILD_STATIC_RUNTIME=OFF
		-DCAPSTONE_BUILD_TESTS=OFF
		-DCAPSTONE_X86_ATT_DISABLE=OFF
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

ExternalProject_Get_Property(capstone-project source_dir)
ExternalProject_Get_Property(capstone-project binary_dir)

add_library(capstone INTERFACE)
add_dependencies(capstone capstone-project)
target_include_directories(capstone SYSTEM INTERFACE ${source_dir}/include)
target_link_libraries(capstone INTERFACE debug ${binary_dir}/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(capstone INTERFACE optimized ${binary_dir}/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
