struct Item { int value; Item(int x):value(x) {} ~Item() noexcept {} };
struct Box { Item member; int tag; };
extern void consume(const Item &);
int branch(bool b) {
 Item a(1);
 if (b) { Item local(2); consume(Item(3)); return local.value; }
 return a.value;
}
Box aggregate_return(bool b) {
 Box x{{1}, 2};
 if (b) return Box{{3}, 4};
 return x;
}
int exception_cleanup(bool b) {
 try { Item x(4); if (b) throw 1; return x.value; }
 catch (int z) { return z; }
}
