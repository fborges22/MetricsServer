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