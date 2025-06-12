cmake_minimum_required(VERSION 3.10)

project(packet-sniffer C)

set(CMAKE_C_STANDARD 99)

include_directories(include)

add_executable(sniffer src/main.c)

target_link_libraries(sniffer pcap)