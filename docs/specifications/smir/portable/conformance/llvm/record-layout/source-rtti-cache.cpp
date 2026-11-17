// Native cache observation; portable normalized RTTI must not copy these bytes.
namespace std { class type_info; }
struct F;
const std::type_info* before = &typeid(F*);
struct B { int value; };
struct F : B {};
const std::type_info* direct = &typeid(F);
const std::type_info* after = &typeid(F*);
