template<bool> struct Pick;
template<> struct Pick<true> { using type = char; };
template<> struct Pick<false> { using type = unsigned char; };
Pick<(__DATE__[7]=='1' && __TIME__[0]=='0' && __TIMESTAMP__[11]=='0' && __FILE__[1]=='r')>::type observed;
