#include <string>
#include <vector>

std::vector<std::string> fixture_events;

extern "C" void fixture_event(const char* event) {
  fixture_events.emplace_back(event);
}

extern "C" int fixture_verify_events() {
  const std::vector<std::string> expected{
      "ctor-101", "ctor-202", "dtor-202", "dtor-101"};
  return fixture_events == expected ? 0 : 1;
}
