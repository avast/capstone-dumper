
set(CAPSTONE_DUMPER_SOURCES
	arm.cpp
	arm64.cpp
	capstone_dumper.cpp
	m68k.cpp
	mips.cpp
	ppc.cpp
	sparc.cpp
	sysz.cpp
	tms320c64x.cpp
	x86.cpp
	xcore.cpp
)

add_executable(capstone-dumper ${CAPSTONE_DUMPER_SOURCES})
target_link_libraries(capstone-dumper capstone keystone)
target_include_directories(capstone-dumper PUBLIC ${PROJECT_SOURCE_DIR}/src/)
install(TARGETS capstone-dumper RUNTIME DESTINATION bin)
