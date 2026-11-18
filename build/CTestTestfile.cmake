# CMake generated Testfile for 
# Source directory: /home/dev/feedback/uid26318
# Build directory: /home/dev/feedback/uid26318/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(fan1_x509 "/home/dev/.local/bin/python" "/home/dev/feedback/uid26318/tests/test_fan1_x509.py" "/home/dev/feedback/uid26318/build/ssldump" "/home/dev/feedback/uid26318/samples/tls1.2_aes256.pcap")
set_tests_properties(fan1_x509 PROPERTIES  _BACKTRACE_TRIPLES "/home/dev/feedback/uid26318/CMakeLists.txt;136;add_test;/home/dev/feedback/uid26318/CMakeLists.txt;0;")
add_test(tls13_pcap "/home/dev/.local/bin/python" "/home/dev/feedback/uid26318/tests/test_tls13.py" "/home/dev/feedback/uid26318/build/ssldump" "/home/dev/feedback/uid26318/samples")
set_tests_properties(tls13_pcap PROPERTIES  _BACKTRACE_TRIPLES "/home/dev/feedback/uid26318/CMakeLists.txt;142;add_test;/home/dev/feedback/uid26318/CMakeLists.txt;0;")
