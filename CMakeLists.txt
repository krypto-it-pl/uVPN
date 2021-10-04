cmake_minimum_required(VERSION 3.1)
project(uVPN)
set(SOURCE_FILES
  src/lib/rsa.c
  src/lib/logger.c
  src/lib/twofish.c
  src/lib/random.c
  src/lib/thpool.c
  src/lib/crc32.c
  src/lib/iniparser.c
  src/lib/utils.c
  src/lib/threads.c
  src/lib/tcpc.c
  src/lib/allocator.c
  src/lib/avl.c
  src/lib/queue.c
  src/lib/exec.c
  src/core/main.c
  src/core/decrypt.c
  src/core/counter.c
  src/core/checksum.c
  src/core/encrypt.c
  src/core/l2_sw.c
  src/core/tap.c
  src/core/tcp.c
  src/core/config.c
)

set(SOURCE_FILES_RSAGEN
  src/lib/rsa.c
  src/tools/rsa_gen.c
)

if (UNIX)
  EXEC_PROGRAM(uname OUTPUT_VARIABLE SYSTEM_NAME)
  if(SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SOURCE_FILES src/lib/linux/tap_int.c)
    list(APPEND SOURCE_FILES src/lib/linux/dns.c)
  elseif(SYSTEM_NAME STREQUAL "OpenBSD")
    list(APPEND SOURCE_FILES src/lib/bsd/tap_int.c)
    list(APPEND SOURCE_FILES src/lib/bsd/dns.c)
  elseif(SYSTEM_NAME STREQUAL "FreeBSD")
    list(APPEND SOURCE_FILES src/lib/bsd/tap_int.c)
    list(APPEND SOURCE_FILES src/lib/bsd/dns.c)
    add_definitions(-DSYS_ENDIAN)
  elseif(SYSTEM_NAME STREQUAL "NetBSD")
    list(APPEND SOURCE_FILES src/lib/bsd/tap_int.c)
    list(APPEND SOURCE_FILES src/lib/bsd/dns.c)
  else()
    message(FATAL_ERROR "Unsupported system")
  endif()
elseif(WIN32)
  message(FATAL_ERROR "Windows is unsupported")
else()
  message(FATAL_ERROR "Unsupported system")
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include_directories(${PROJECT_SOURCE_DIR}/src/lib ${GMP_INCLUDES})
find_package(GMP REQUIRED)
find_package(Threads REQUIRED)
set(MAX_CONNS "64" CACHE STRING "Max open connections")
add_definitions(-DMAX_CONNS=${MAX_CONNS})
add_executable(uVPN ${SOURCE_FILES})
target_link_libraries(uVPN ${GMP_LIBRARIES} Threads::Threads)

include_directories(${PROJECT_SOURCE_DIR}/src/lib ${GMP_INCLUDES})
add_executable(uVPN_rsagen ${SOURCE_FILES_RSAGEN})
target_link_libraries(uVPN_rsagen ${GMP_LIBRARIES})

install(TARGETS uVPN uVPN_rsagen RUNTIME DESTINATION bin)
