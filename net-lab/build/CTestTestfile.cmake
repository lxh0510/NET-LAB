# CMake generated Testfile for 
# Source directory: D:/net-lab
# Build directory: D:/net-lab/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(eth_in "D:/net-lab/build/eth_in.exe" "D:/net-lab/testing/data/eth_in")
set_tests_properties(eth_in PROPERTIES  _BACKTRACE_TRIPLES "D:/net-lab/CMakeLists.txt;117;add_test;D:/net-lab/CMakeLists.txt;0;")
add_test(eth_out "D:/net-lab/build/eth_out.exe" "D:/net-lab/testing/data/eth_out")
set_tests_properties(eth_out PROPERTIES  _BACKTRACE_TRIPLES "D:/net-lab/CMakeLists.txt;122;add_test;D:/net-lab/CMakeLists.txt;0;")
add_test(arp_test "D:/net-lab/build/arp_test.exe" "D:/net-lab/testing/data/arp_test")
set_tests_properties(arp_test PROPERTIES  _BACKTRACE_TRIPLES "D:/net-lab/CMakeLists.txt;127;add_test;D:/net-lab/CMakeLists.txt;0;")
add_test(ip_test "D:/net-lab/build/ip_test.exe" "D:/net-lab/testing/data/ip_test")
set_tests_properties(ip_test PROPERTIES  _BACKTRACE_TRIPLES "D:/net-lab/CMakeLists.txt;132;add_test;D:/net-lab/CMakeLists.txt;0;")
add_test(ip_frag_test "D:/net-lab/build/ip_frag_test.exe" "D:/net-lab/testing/data/ip_frag_test")
set_tests_properties(ip_frag_test PROPERTIES  _BACKTRACE_TRIPLES "D:/net-lab/CMakeLists.txt;137;add_test;D:/net-lab/CMakeLists.txt;0;")
add_test(icmp_test "D:/net-lab/build/icmp_test.exe" "D:/net-lab/testing/data/icmp_test")
set_tests_properties(icmp_test PROPERTIES  _BACKTRACE_TRIPLES "D:/net-lab/CMakeLists.txt;142;add_test;D:/net-lab/CMakeLists.txt;0;")
