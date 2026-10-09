CXX ?= g++
CPPFLAGS := -Isrc -Isrc/inprocess
STRICT := -std=c++20 -O2 -g -Wall -Wextra -Wpedantic -Werror
BUILD := build
FIXTURES := $(BUILD)/fixtures
CORE := src/inprocess/elf_image.cpp src/inprocess/mapped_image.cpp src/inprocess/dependency_graph.cpp
PROCESS := src/process_control.cpp
PTRACE := src/ptrace_control.cpp
MAPS := src/process_maps.cpp
TRACE := src/trace_session.cpp
REMOTE := src/remote_modules.cpp

.PHONY: all clean fixtures parser-test mapping-test graph-test process-control-test process-maps-test trace-session-test ptrace-control-test remote-memory-test remote-modules-test owned-process-test test release-test sanitizers

all: $(BUILD)/elf-loader

$(BUILD):
	mkdir -p $@

$(FIXTURES):
	mkdir -p $@

$(BUILD)/elf-loader: src/loader.cpp src/process_control.hpp $(PROCESS) src/process_maps.hpp $(MAPS) src/trace_session.hpp $(TRACE) src/ptrace_control.hpp $(PTRACE) src/remote_modules.hpp $(REMOTE) tests/fixtures/host.cpp $(CORE) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -rdynamic -o $@ src/loader.cpp $(PROCESS) $(MAPS) $(TRACE) $(PTRACE) $(REMOTE) tests/fixtures/host.cpp $(CORE) -ldl

$(FIXTURES)/libfixturedep.so: tests/fixtures/dependency.cpp tests/fixtures/dependency.map | $(FIXTURES)
	$(CXX) -std=c++20 -shared -fPIC -O2 -g -Wl,--version-script=tests/fixtures/dependency.map -Wl,-soname,libfixturedep.so -o $@ $<

$(FIXTURES)/libtarget.so: tests/fixtures/target.cpp $(FIXTURES)/libfixturedep.so | $(FIXTURES)
	$(CXX) -std=c++20 -shared -fPIC -O2 -g -fno-omit-frame-pointer -Wl,-z,relro,-z,now -Wl,-z,pack-relative-relocs -Wl,--hash-style=both -Wl,-rpath,'$$ORIGIN' -L$(FIXTURES) -o $@ $< -lfixturedep

$(FIXTURES)/libdiamond_leaf.so: tests/fixtures/diamond_leaf.cpp | $(FIXTURES)
	$(CXX) -std=c++20 -shared -fPIC -O2 -g -Wl,-soname,libdiamond_leaf.so -o $@ $<

$(FIXTURES)/libdiamond_left.so: tests/fixtures/diamond_left.cpp $(FIXTURES)/libdiamond_leaf.so | $(FIXTURES)
	$(CXX) -std=c++20 -shared -fPIC -O2 -g -Wl,-soname,libdiamond_left.so -Wl,-rpath,'$$ORIGIN' -L$(FIXTURES) -o $@ $< -ldiamond_leaf

$(FIXTURES)/libdiamond_right.so: tests/fixtures/diamond_right.cpp $(FIXTURES)/libdiamond_leaf.so | $(FIXTURES)
	$(CXX) -std=c++20 -shared -fPIC -O2 -g -Wl,-soname,libdiamond_right.so -Wl,-rpath,'$$ORIGIN' -L$(FIXTURES) -o $@ $< -ldiamond_leaf

$(FIXTURES)/libdiamond_root.so: tests/fixtures/diamond_root.cpp $(FIXTURES)/libdiamond_left.so $(FIXTURES)/libdiamond_right.so | $(FIXTURES)
	$(CXX) -std=c++20 -shared -fPIC -O2 -g -Wl,-soname,libdiamond_root.so -Wl,-rpath,'$$ORIGIN' -L$(FIXTURES) -o $@ $< -Wl,--no-as-needed -ldiamond_left -ldiamond_right

fixtures: $(FIXTURES)/libtarget.so $(FIXTURES)/libdiamond_root.so

$(BUILD)/parser-test: tests/loader_parser_test.cpp src/inprocess/elf_image.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ $^

$(BUILD)/mapping-test: tests/loader_mapping_test.cpp src/inprocess/elf_image.cpp src/inprocess/mapped_image.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ $^

$(BUILD)/graph-test: tests/loader_graph_test.cpp src/inprocess/elf_image.cpp src/inprocess/dependency_graph.cpp src/inprocess/symbol_resolver.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ $^ -ldl

$(BUILD)/owned-process-test: tests/loader_owned_process_test.cpp | $(BUILD)
	$(CXX) $(STRICT) -o $@ $<

$(BUILD)/process-control-test: tests/process_control_test.cpp src/process_control.hpp $(PROCESS) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ tests/process_control_test.cpp $(PROCESS)

$(BUILD)/process-maps-test: tests/process_maps_test.cpp src/process_maps.hpp $(MAPS) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ tests/process_maps_test.cpp $(MAPS)

$(BUILD)/trace-session-test: tests/trace_session_test.cpp src/trace_session.hpp $(TRACE) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -pthread -o $@ tests/trace_session_test.cpp $(TRACE)

$(BUILD)/ptrace-control-test: tests/ptrace_control_test.cpp src/ptrace_control.hpp $(PTRACE) src/process_maps.hpp $(MAPS) src/trace_session.hpp $(TRACE) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ tests/ptrace_control_test.cpp $(PTRACE) $(MAPS) $(TRACE)

$(BUILD)/remote-memory-test: tests/remote_memory_test.cpp src/ptrace_control.hpp $(PTRACE) src/process_maps.hpp $(MAPS) src/trace_session.hpp $(TRACE) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -o $@ tests/remote_memory_test.cpp $(PTRACE) $(MAPS) $(TRACE)

$(BUILD)/remote-modules-test: tests/remote_modules_test.cpp src/remote_modules.hpp $(REMOTE) src/process_maps.hpp $(MAPS) src/inprocess/elf_image.cpp | $(BUILD)
	$(CXX) $(CPPFLAGS) $(STRICT) -rdynamic -o $@ tests/remote_modules_test.cpp $(REMOTE) $(MAPS) src/inprocess/elf_image.cpp

parser-test: fixtures $(BUILD)/parser-test
	./$(BUILD)/parser-test ./$(FIXTURES)/libtarget.so

mapping-test: fixtures $(BUILD)/mapping-test
	./$(BUILD)/mapping-test ./$(FIXTURES)/libtarget.so

graph-test: fixtures $(BUILD)/graph-test
	LD_LIBRARY_PATH="$(CURDIR)/$(FIXTURES)" ./$(BUILD)/graph-test ./$(FIXTURES)/libtarget.so ./$(FIXTURES)/libdiamond_root.so

process-control-test: $(BUILD)/process-control-test
	./$(BUILD)/process-control-test

process-maps-test: $(BUILD)/process-maps-test
	./$(BUILD)/process-maps-test

trace-session-test: $(BUILD)/trace-session-test
	./$(BUILD)/trace-session-test

ptrace-control-test: all $(BUILD)/ptrace-control-test
	./$(BUILD)/ptrace-control-test ./$(BUILD)/elf-loader

remote-memory-test: all $(BUILD)/remote-memory-test
	./$(BUILD)/remote-memory-test ./$(BUILD)/elf-loader

remote-modules-test: all $(BUILD)/remote-modules-test
	./$(BUILD)/remote-modules-test ./$(BUILD)/elf-loader

owned-process-test: all fixtures $(BUILD)/owned-process-test
	LD_LIBRARY_PATH="$(CURDIR)/$(FIXTURES)" ./$(BUILD)/owned-process-test ./$(BUILD)/elf-loader ./$(FIXTURES)/libtarget.so

test: parser-test mapping-test graph-test process-control-test process-maps-test trace-session-test ptrace-control-test remote-memory-test remote-modules-test owned-process-test
	LD_LIBRARY_PATH="$(CURDIR)/$(FIXTURES)" ./$(BUILD)/elf-loader ./$(FIXTURES)/libtarget.so

release-test: all fixtures $(BUILD)/parser-test $(BUILD)/mapping-test $(BUILD)/graph-test $(BUILD)/process-control-test $(BUILD)/process-maps-test $(BUILD)/trace-session-test $(BUILD)/ptrace-control-test $(BUILD)/remote-memory-test $(BUILD)/remote-modules-test $(BUILD)/owned-process-test
	./tests/run_loader_release_tests.sh

sanitizers: fixtures
	./tests/run_loader_sanitizers.sh

clean:
	rm -rf $(BUILD)
