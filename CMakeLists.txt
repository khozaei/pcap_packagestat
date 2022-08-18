cmake_minimum_required(VERSION 3.10)

project(pcap_packetstat)

set ( CMAKE_C_FLAGS "-g -Wall")
include_directories(include)
add_executable(pcap_packetstat main.c source/packet.c)
set_property(TARGET pcap_packetstat PROPERTY C_STANDARD 11)
target_link_libraries(pcap_packetstat pcap)
