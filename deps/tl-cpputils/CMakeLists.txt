
include(ExternalProject)

ExternalProject_Add(tl-cpputils-project
	GIT_REPOSITORY https://github.com/avast-tl/tl-cpputils
	GIT_TAG v1.0
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

ExternalProject_Get_Property(tl-cpputils-project source_dir)
ExternalProject_Get_Property(tl-cpputils-project binary_dir)

add_library(tl-cpputils INTERFACE)
add_dependencies(tl-cpputils tl-cpputils-project)
target_include_directories(tl-cpputils SYSTEM INTERFACE ${source_dir}/include)
target_link_libraries(tl-cpputils INTERFACE debug ${binary_dir}/src/tl-cpputils/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}tl-cpputils${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(tl-cpputils INTERFACE optimized ${binary_dir}/src/tl-cpputils/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}tl-cpputils${CMAKE_STATIC_LIBRARY_SUFFIX})
