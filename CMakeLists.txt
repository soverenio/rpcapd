cmake_minimum_required(VERSION 3.12)

project(rpcapd C)

option(PROFILING_ENABLE "Enable code profiling" OFF)

list(PREPEND CMAKE_MODULE_PATH  "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
list(PREPEND CMAKE_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# find pcap library with minimum required version to be 1.10
find_package(PCAP 1.10.0 REQUIRED)
if(NOT HAVE_PCAP_INIT)
    message(FATAL_ERROR "pcap_init function was not found")
endif()

include_directories(BEFORE SYSTEM ${PCAP_INCLUDE_DIR})
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# find pthread library
set(CMAKE_THREAD_PREFER_PTHREAD ON)
find_package(Threads)
if(NOT CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "pthread library not found")
endif()

if(PROFILING_ENABLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
endif()

check_function_exists(crypt HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
if(HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
    set(HAVE_CRYPT TRUE)
else(HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
    check_library_exists(crypt crypt "" HAVE_CRYPT_IN_LIBCRYPT)
    if(HAVE_CRYPT_IN_LIBCRYPT)
        set(RPCAPD_LINK_LIBRARIES ${RPCAPD_LINK_LIBRARIES} crypt)
        set(HAVE_CRYPT TRUE)
    else(HAVE_CRYPT_IN_LIBCRYPT)
        message(FATAL_ERROR "crypt() not found")
    endif()
endif()

#
# Based on
#
#    https://github.com/commonmark/cmark/blob/master/FindAsan.cmake
#
# The MIT License (MIT)
#
# Copyright (c) 2013 Matthew Arsenault
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# Test if the each of the sanitizers in the ENABLE_SANITIZERS list are
# supported by the compiler, and, if so, adds the appropriate flags to
# CMAKE_C_FLAGS, CMAKE_CXX_FLAGS, and SANITIZER_FLAGS.  If not, it fails.
#
# Do this last, in the hope that it will prevent configuration on Linux
# from somehow deciding it doesn't need -lpthread when building rpcapd
# (it does require it, but somehow, in some mysterious fashion that no
# obvious CMake debugging flag reveals, it doesn't realize that if we
# turn sanitizer stuff on).
#
set(SANITIZER_FLAGS "")
foreach(sanitizer IN LISTS ENABLE_SANITIZERS)
    # Set -Werror to catch "argument unused during compilation" warnings

    message(STATUS "Checking sanitizer ${sanitizer}")
    set(sanitizer_variable "sanitize_${sanitizer}")
    set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize=${sanitizer}")
    check_c_compiler_flag("-fsanitize=${sanitizer}" ${sanitizer_variable})
    if(${${sanitizer_variable}})
        set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fsanitize=${sanitizer}")
        message(STATUS "${sanitizer} sanitizer supported using -fsanitizer=${sanitizer}")
    else()
        #
        # Try the versions supported prior to Clang 3.2.
        # If the sanitizer is "address", try -fsanitize-address.
        # If it's "undefined", try -fcatch-undefined-behavior.
        # Otherwise, give up.
        #
        set(sanitizer_variable "OLD_${sanitizer_variable}")
        if ("${sanitizer}" STREQUAL "address")
            set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize-address")
            check_c_compiler_flag("-fsanitize-address" ${sanitizer_variable})
            if(${${sanitizer_variable}})
                set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fsanitize-address")
                message(STATUS "${sanitizer} sanitizer supported using -fsanitize-address")
            else()
                message(FATAL_ERROR "${sanitizer} isn't a supported sanitizer")
            endif()
        elseif("${sanitizer}" STREQUAL "undefined")
            set(CMAKE_REQUIRED_FLAGS "-Werror -fcatch-undefined-behavior")
            check_c_compiler_flag("-fcatch-undefined-behavior" ${sanitizer_variable})
            if(${${sanitizer_variable}})
                set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fcatch-undefined-behavior")
                message(STATUS "${sanitizer} sanitizer supported using catch-undefined-behavior")
            else()
                message(FATAL_ERROR "${sanitizer} isn't a supported sanitizer")
            endif()
        else()
            message(FATAL_ERROR "${sanitizer} isn't a supported sanitizer")
        endif()
    endif()

    unset(CMAKE_REQUIRED_FLAGS)
endforeach()

if(NOT "${SANITIZER_FLAGS}" STREQUAL "")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -g ${SANITIZER_FLAGS} -fno-omit-frame-pointer -fno-optimize-sibling-calls")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O1 -g ${SANITIZER_FLAGS} -fno-omit-frame-pointer -fno-optimize-sibling-calls")
endif()

#
# OpenSSL/libressl.
#
find_package(OpenSSL)
if(OPENSSL_FOUND)
  #
  # We have OpenSSL.
  #
  include_directories(BEFORE SYSTEM ${OPENSSL_INCLUDE_DIR})
  set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${OPENSSL_LIBRARIES})

  #
  # The find_package() module CMake provides for OpenSSL uses does not
  # give us a defined indication of whether it found OpenSSL with
  # pkg-config or not.  We need to know that as, if it was found with
  # pkg-config, we should set the Requires.private value in libpcap.pc
  # to include its package name, openssl, otherwise we should add the
  # names for the static libraries to Libs.private.
  #
  # On UN*X, FindOpenSSL happens to use pkg-config to find OpenSSL, but
  # it doesn't appear to be documented as doing so; therefore, we don't
  # assume that, if we got here, we have pkg-config.
  #
  # So we use pkg_get_link_info() to run pkg-config ourselves, both
  # because FindOpenSSL doesn't set the OPENSSL_LDFLAGS or
  # OPENSSL_STATIC_LDFLAGS variables and because, for reasons explained
  # in the comment before the pkg_get_link_info() macro, even if it did,
  # it wouldn't be what we want anyway.
  #
  if (PKG_CONFIG_EXECUTABLE)
    pkg_get_link_info(OPENSSL openssl)
    if (OPENSSL_FOUND_WITH_PKG_CONFIG)
      #
      # pkg-config failed; assume that means that there is no openssl
      # package for it to find.  Just add OPENSSL_LIBRARIES to
      # LIBS_PRIVATE AND LIBS_STATIC, as that's the
      # best we can do. XXX - need list of -l and -L flags to add....
      #
      set(LIBS "${LIBS} ${OPENSSL_LIBS}")
      set(LIBS_STATIC "${LIBS_STATIC} ${OPENSSL_LIBS_STATIC}")
      set(REQUIRES_PRIVATE "${REQUIRES_PRIVATE} ${OPENSSL_PACKAGE_NAME}")
    endif()
  else()
    # Get it from OPENSSL_LIBRARIES
    foreach(_lib IN LISTS OPENSSL_LIBRARIES)
      #
      # Get the directory in which the library resides.
      #
      get_filename_component(_lib_directory "${_lib}" DIRECTORY)

      #
      # Is the library directory in CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES?
      # (See comment above on why we use that.)
      #
      list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${_lib_directory}" _lib_index)
      if(_lib_index EQUAL -1)
        #
        # No, so add a -L flag to get the linker to search in that
        # directory.
        #
        set(LIBS "${LIBS} -L${_lib_directory}")
        set(LIBS_STATIC "${LIBS_STATIC} -L${_lib_directory}")
        set(LIBS_PRIVATE "${LIBS_PRIVATE} -L${_lib_directory}")
      endif()

      #
      # Get the file name of the library, without the extension.
      #
      get_filename_component(_lib_filename "${_lib}" NAME_WE)

      #
      # Strip off the "lib" prefix to get the library name, and
      # add a -l flag based on that.
      #
      string(REGEX REPLACE "^lib" "" _library_name "${_lib_filename}")
      set(LIBS "${LIBS} -l${_library_name}")
      set(LIBS_STATIC "${LIBS_STATIC} -l${_library_name}")
      set(LIBS_PRIVATE "${LIBS_PRIVATE} -l${_library_name}")
    endforeach()
  endif()

  add_definitions("-DHAVE_OPENSSL=1")
endif(OPENSSL_FOUND)

include(cmake/missing.cmake)

#
# Do we have getspnam()?
#
check_function_exists(getspnam HAVE_GETSPNAM)

#
# Find library needed for getaddrinfo.
# NOTE: if you hand check_library_exists as its last argument a variable
# that's been set, it skips the test, so we need different variables.
#
include(CheckLibraryExists)
check_function_exists(getaddrinfo STDLIBS_HAVE_GETADDRINFO)
if(NOT STDLIBS_HAVE_GETADDRINFO)
    check_library_exists(xnet getaddrinfo "" LIBXNET_HAS_GETADDRINFO)
    if(LIBXNET_HAS_GETADDRINFO)
        set(RPCAPD_LINK_LIBRARIES ${RPCAPD_LINK_LIBRARIES} xnet)
    else(LIBXNET_HAS_GETADDRINFO)
        include(CMakePushCheckState)
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES nsl)
        check_library_exists(socket getaddrinfo "" LIBSOCKET_HAS_GETADDRINFO)
        cmake_pop_check_state()
        if(LIBSOCKET_HAS_GETADDRINFO)
            set(RPCAPD_LINK_LIBRARIES ${RPCAPD_LINK_LIBRARIES} socket nsl)
        endif()
    endif()
endif()

add_executable(rpcapd
    src/daemon.c
    src/fileconf.c
    src/log.c
    src/rpcapd.c
    src/rpcap-protocol.c
    src/sockutils.c
    src/sslutils.c
    src/fmtutils.c
    ${MISSING_C}
)

if(NOT "${C_ADDITIONAL_FLAGS}" STREQUAL "")
    message(STATUS "C_ADDITIONAL_FLAGS: " ${C_ADDITIONAL_FLAGS})
    set_target_properties(rpcapd
            PROPERTIES
            COMPILE_FLAGS ${C_ADDITIONAL_FLAGS})
endif()

if(NOT "${SANITIZER_FLAGS}" STREQUAL "")
    message(STATUS "SANITIZER_FLAGS: " ${SANITIZER_FLAGS})
    set_target_properties(rpcapd
            PROPERTIES
            LINK_FLAGS "${SANITIZER_FLAGS}")
endif()

#
# By default, build rpcapd universal with the appropriate set of
# architectures for the OS on which we're doing the build.
#
if(APPLE AND "${CMAKE_OSX_ARCHITECTURES}" STREQUAL "")
    #
    # Get the major version of Darwin.
    #
    string(REGEX MATCH "^([0-9]+)" SYSTEM_VERSION_MAJOR "${CMAKE_SYSTEM_VERSION}")

    if(SYSTEM_VERSION_MAJOR EQUAL 9)
        #
        # Leopard.    Build for 32-bit x86 and 32-bit PowerPC, with
        # 32-bit x86 first.
        #
        set(OSX_PROGRAM_ARCHITECTURES "i386;ppc")
    elseif(SYSTEM_VERSION_MAJOR EQUAL 10)
        #
        # Snow Leopard.    Build for x86-64 and 32-bit x86, with
        # x86-64 first.
        #
        set(OSX_PROGRAM_ARCHITECTURES "x86_64;i386")
    else()
        #
        # Post-Snow Leopard.    Build only for x86-64.
        # XXX - update if and when Apple adds ARM-based Macs.
        # (You're on your own for iOS etc.)
        #
        set(OSX_PROGRAM_ARCHITECTURES "x86_64")
    endif()

    set_target_properties(rpcapd PROPERTIES
        OSX_ARCHITECTURES "${OSX_PROGRAM_ARCHITECTURES}")
endif()

target_link_libraries(rpcapd ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

if(OPENSSL_FOUND)
    target_link_libraries(rpcapd ${OPENSSL_LIBRARIES})
endif()

######################################
# Install rpcap daemon and man pages
######################################

#
# "Define GNU standard installation directories", which actually
# are also defined, to some degree, by autotools, and at least
# some of which are general UN*X conventions.
#
include(GNUInstallDirs)

set(MANADMIN_EXPAND rpcapd.manadmin.in)

set(MANFILE_EXPAND rpcapd-config.manfile.in)

#
# On UN*X, we put it in the sbin directory.
#
# XXX - the Linux Filesystem Hierarchy Standard says /usr/sbin
# is for daemons, but some other systems use /usr/libexec instead.
# However, since some users might, instead of having rpcapd be
# launched by inetd/xinetd/launchd/systemd, just run it on a
# machine when remote capture is to be done, a case can be made
# for the sbin directory even on systems with /usr/libexec.
#
install(TARGETS rpcapd DESTINATION ${CMAKE_INSTALL_SBINDIR})
