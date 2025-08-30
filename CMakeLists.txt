cmake_minimum_required(VERSION 3.12)
project(MetricsServer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Binary name
set(METRICS_SERVER_TARGET metrics_server)

# Source file (save the C++ code above as metrics_server.cpp next to this CMakeLists)
add_executable(${METRICS_SERVER_TARGET} metrics_server.cpp)

if (WIN32)
  # Windows libs
  target_link_libraries(${METRICS_SERVER_TARGET} PRIVATE Ws2_32 Iphlpapi Pdh)
else()
  # POSIX threads
  find_package(Threads REQUIRED)
  target_link_libraries(${METRICS_SERVER_TARGET} PRIVATE Threads::Threads)
endif()

# Install to /usr/local/bin by default (CMAKE_INSTALL_PREFIX)
install(TARGETS ${METRICS_SERVER_TARGET} RUNTIME DESTINATION bin)
# Install the systemd service unit and default env file on Linux
if(UNIX AND NOT APPLE)
# Service unit expects the binary at /usr/local/bin/metrics_server by default
  install(FILES packaging/metrics-server.service DESTINATION lib/systemd/system)
  install(FILES packaging/metrics-server.default DESTINATION etc/default RENAME metrics-server)
endif()

# --- CPack (packaging) ---
# Generate installable packages from existing install() rules
# Usage:
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j
#   cmake --build build --target package

# Package metadata
set(CPACK_PACKAGE_NAME "Metrics Server")
set(CPACK_PACKAGE_VENDOR "BorgesHQ")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cross-platform Metrics HTTP API in C++")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_CONTACT "muc0hllvw@mozmail.com")

# License file :O
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

# Default generators per platform
if(UNIX AND NOT APPLE)
  # Produce .deb, .rpm and .tar.gz
  set(CPACK_GENERATOR "DEB;RPM;TGZ")
  # Debian-specific
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Your Name")
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  # RPM-specific
  set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
elseif(WIN32)
  # ZIP always available; NSIS requires NSIS installed
  set(CPACK_GENERATOR "ZIP;NSIS")
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "Metrics Server")
endif()

include(CPack)
