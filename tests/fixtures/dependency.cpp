thread_local int fixture_tls = 7;

extern "C" int versioned_value_v1() { return 11; }
extern "C" int versioned_value_v2() { return 29; }

asm(".symver versioned_value_v1,versioned_value@FIXTURE_1.0");
asm(".symver versioned_value_v2,versioned_value@@FIXTURE_2.0");
