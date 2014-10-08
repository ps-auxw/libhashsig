cmake_minimum_required(VERSION 2.6)
project(HASHSIG C)

# Set compiler and linker flags.
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 -ftrapv -D_FORTIFY_SOURCE=2 -fPIC -O3 -Wall -pedantic -std=c99 -Werror")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now,--build-id=none")
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_C_FLAGS "-${CMAKE_C_FLAGS} fstack-protector-all -Wstack-protector -ftrapv -D_FORTIFY_SOURCE=2 -fPIC -O3 -Wall -pedantic -Werror")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now,--build-id=none")
endif ()

# Set up basic directories.
include_directories(${HASHSIG_SOURCE_DIR}/include) 
include_directories(${HASHSIG_SOURCE_DIR}/src) 
include_directories(${HASHSIG_SOURCE_DIR}/src/keccak) 
include_directories(${CMAKE_BINARY_DIR}/include) 

# Generate main header file with correct version number.
set(HASHSIG_VERSION_MAJOR 0)
set(HASHSIG_VERSION_MINOR 9)
set(HASHSIG_VERSION_MICRO 0)
set(HASHSIG_VERSION_STRING ${HASHSIG_VERSION_MAJOR}.${HASHSIG_VERSION_MINOR}.${HASHSIG_VERSION_MICRO})
set(HASHSIG_SOVERSION_STRING ${HASHSIG_VERSION_MAJOR}.${HASHSIG_VERSION_MINOR})
configure_file("${HASHSIG_SOURCE_DIR}/include/hashsig.h.in" "${CMAKE_BINARY_DIR}/include/hashsig.h")

# Generate pkg-config file.
configure_file("${HASHSIG_SOURCE_DIR}/src/libhashsig.pc.in" "${CMAKE_BINARY_DIR}/src/libhashsig.pc")

# Build both static and synamic libraries.
add_library(hashsig-shared SHARED src/hashsig.c src/ldwm.c src/lmfs.c src/util.c src/keccak/KeccakF-1600-opt64.c src/keccak/KeccakHash.c src/keccak/KeccakSponge.c src/keccak/keccak.c)
add_library(hashsig-static STATIC src/hashsig.c src/ldwm.c src/lmfs.c src/util.c src/keccak/KeccakF-1600-opt64.c src/keccak/KeccakHash.c src/keccak/KeccakSponge.c src/keccak/keccak.c)

set_target_properties(hashsig-shared PROPERTIES OUTPUT_NAME hashsig VERSION ${HASHSIG_VERSION_STRING} SOVERSION ${HASHSIG_SOVERSION_STRING} CLEAN_DIRECT_OUTPUT 1 LIBRARY_OUTPUT_DIRECTORY lib)
set_target_properties(hashsig-static PROPERTIES OUTPUT_NAME hashsig VERSION ${HASHSIG_VERSION_STRING} CLEAN_DIRECT_OUTPUT 1 ARCHIVE_OUTPUT_DIRECTORY lib)

# Build stand alone example program
add_executable(hashsig-example examples/hashsig-example.c)
target_link_libraries(hashsig-example hashsig-static)
set_target_properties(hashsig-example PROPERTIES CLEAN_DIRECT_OUTPUT 1 RUNTIME_OUTPUT_DIRECTORY bin)

# Set installation destinations.
install(TARGETS hashsig-shared DESTINATION lib)
install(TARGETS hashsig-static DESTINATION lib)
install(FILES "${CMAKE_BINARY_DIR}/src/libhashsig.pc" DESTINATION lib/pkgconfig)
install(FILES "${CMAKE_BINARY_DIR}/include/hashsig.h" DESTINATION include)
install(FILES doc/libhashsig.3 DESTINATION share/man/man3)

# Try to build test programs that depend on libsodium.
find_package(PkgConfig)
pkg_check_modules(PC_LIBSODIUM libsodium)
if (PC_LIBSODIUM_FOUND)
	add_executable(hashsig-test src/tests/hashsig-test.c)
	target_link_libraries(hashsig-test hashsig-static ${PC_LIBSODIUM_LIBRARIES})
	set_target_properties(hashsig-test PROPERTIES CLEAN_DIRECT_OUTPUT 1 RUNTIME_OUTPUT_DIRECTORY bin)

	add_executable(hashsig-test-rnd src/tests/hashsig-test-rnd.c)
	target_link_libraries(hashsig-test-rnd hashsig-static ${PC_LIBSODIUM_LIBRARIES})
	set_target_properties(hashsig-test-rnd PROPERTIES CLEAN_DIRECT_OUTPUT 1 RUNTIME_OUTPUT_DIRECTORY bin)

	add_executable(hashsig-test-ldwm src/tests/hashsig-test-ldwm.c)
	target_link_libraries(hashsig-test-ldwm hashsig-static ${PC_LIBSODIUM_LIBRARIES})
	set_target_properties(hashsig-test-ldwm PROPERTIES CLEAN_DIRECT_OUTPUT 1 RUNTIME_OUTPUT_DIRECTORY bin)
endif (PC_LIBSODIUM_FOUND)
