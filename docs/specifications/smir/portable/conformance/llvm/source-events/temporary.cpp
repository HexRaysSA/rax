struct Item { int value; Item(int x):value(x) {} ~Item() {} };
extern void consume(const Item &);
void reference_temporary() { const Item &ref = Item(9); consume(ref); }
int loops(int n) { int x=0; for(int i=0;i<n;++i) { if(i==2) continue; x+=i; if(x>20)break; } return x; }
