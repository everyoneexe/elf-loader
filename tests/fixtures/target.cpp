#include <stdexcept>

extern "C" int versioned_value();
asm(".symver versioned_value,versioned_value@FIXTURE_1.0");

extern "C" void fixture_event(const char* event);

extern thread_local int fixture_tls;
static int constructor_state = 0;
static int relative_values[96] = {};
static int* relative_pointers[96] = {};

static int implementation() { return 5; }
extern "C" void* choose_implementation() { return reinterpret_cast<void*>(&implementation); }
extern "C" int fixture_ifunc() __attribute__((ifunc("choose_implementation")));

__attribute__((constructor(101))) static void first_constructor() {
  for (int index = 0; index < 96; ++index) relative_pointers[index] = &relative_values[index];
  constructor_state = 1;
  fixture_event("ctor-101");
}

__attribute__((constructor(202))) static void second_constructor() {
  constructor_state = constructor_state == 1 ? 2 : -1;
  fixture_event("ctor-202");
}

__attribute__((destructor(202))) static void second_destructor() {
  fixture_event("dtor-202");
}

__attribute__((destructor(101))) static void first_destructor() {
  fixture_event("dtor-101");
}

static int exception_probe() {
  try {
    throw std::runtime_error("fixture");
  } catch (const std::runtime_error&) {
    return 13;
  }
}

extern "C" int fixture_probe() {
  const bool relative_ok = relative_pointers[73] == &relative_values[73];
  return constructor_state == 2 && fixture_tls == 7 && fixture_ifunc() == 5 &&
                 versioned_value() == 11 && exception_probe() == 13 && relative_ok
             ? 0
             : 1;
}
