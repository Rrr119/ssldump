# CMake generated Testfile for 
# Source directory: /home/dev/feedback/uid34533
# Build directory: /home/dev/feedback/uid34533/build-asan
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(fan1_x509 "/home/dev/.local/bin/python" "/home/dev/feedback/uid34533/tests/test_fan1_x509.py" "/home/dev/feedback/uid34533/build-asan/ssldump" "/home/dev/feedback/uid34533/samples/tls1.2_aes256.pcap")
set_tests_properties(fan1_x509 PROPERTIES  _BACKTRACE_TRIPLES "/home/dev/feedback/uid34533/CMakeLists.txt;136;add_test;/home/dev/feedback/uid34533/CMakeLists.txt;0;")
add_test(keylog_tls12_pcap "/home/dev/.local/bin/python" "/home/dev/feedback/uid34533/tests/test_keylog.py" "/home/dev/feedback/uid34533/build-asan/ssldump" "/home/dev/feedback/uid34533/samples" "tls12")
set_tests_properties(keylog_tls12_pcap PROPERTIES  _BACKTRACE_TRIPLES "/home/dev/feedback/uid34533/CMakeLists.txt;142;add_test;/home/dev/feedback/uid34533/CMakeLists.txt;0;")
add_test(keylog_tls13_pcap "/home/dev/.local/bin/python" "/home/dev/feedback/uid34533/tests/test_keylog.py" "/home/dev/feedback/uid34533/build-asan/ssldump" "/home/dev/feedback/uid34533/samples" "tls13")
set_tests_properties(keylog_tls13_pcap PROPERTIES  _BACKTRACE_TRIPLES "/home/dev/feedback/uid34533/CMakeLists.txt;149;add_test;/home/dev/feedback/uid34533/CMakeLists.txt;0;")
add_test(keylog_multiflow_pcap "/home/dev/.local/bin/python" "/home/dev/feedback/uid34533/tests/test_keylog.py" "/home/dev/feedback/uid34533/build-asan/ssldump" "/home/dev/feedback/uid34533/samples" "multiflow")
set_tests_properties(keylog_multiflow_pcap PROPERTIES  _BACKTRACE_TRIPLES "/home/dev/feedback/uid34533/CMakeLists.txt;156;add_test;/home/dev/feedback/uid34533/CMakeLists.txt;0;")
