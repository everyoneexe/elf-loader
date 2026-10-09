extern "C" int diamond_left();
extern "C" int diamond_right();
extern "C" int diamond_probe() { return diamond_left() + diamond_right(); }
