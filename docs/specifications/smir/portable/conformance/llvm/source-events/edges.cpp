int parallel_edges(int x) { switch(x) { case 0: case 1: return 3; default: return 4; } }
int constant_branch() { if constexpr(false) return 1; else return 2; }
