struct Record { int x; };
int local() { Record a{3}; return a.x; }
