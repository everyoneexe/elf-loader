#include "process_control.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <unistd.h>

int main() {
  try {
    const elfloader::ProcessInfo self = elfloader::inspect_process(getpid());
    if (self.pid != getpid() || self.name.empty() || self.executable.empty() ||
        self.state == '?') {
      std::cerr << "self process inspection failed\n";
      return 1;
    }

    char shell[] = "sh";
    char shell_option[] = "-c";
    char exit_command[] = "exit 7";
    char* exit_arguments[]{shell, shell_option, exit_command, nullptr};
    const elfloader::OwnedChildResult exited = elfloader::run_owned_process(
        exit_arguments, std::chrono::seconds(2));
    if (exited.timed_out || exited.exit_code != 7 || exited.term_signal != 0) {
      std::cerr << "owned child exit propagation failed\n";
      return 1;
    }

    char sleep_command[] = "sleep 5";
    char* sleep_arguments[]{shell, shell_option, sleep_command, nullptr};
    const elfloader::OwnedChildResult timed_out = elfloader::run_owned_process(
        sleep_arguments, std::chrono::milliseconds(50));
    if (!timed_out.timed_out || timed_out.exit_code != -1 ||
        timed_out.term_signal == 0) {
      std::cerr << "owned child timeout failed\n";
      return 1;
    }

    std::cout << "process_control=0\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "process-control-test: " << error.what() << '\n';
    return 1;
  }
}
