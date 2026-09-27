/* Genuine compiler-selected main/wmain entry/startup: no custom entry,
   no direct ExitProcess and no replacement startup object. */
#if defined(WIDE)
int wmain(int argc, __WCHAR_TYPE__ **argv) { return argc < 1 || argv == 0 || argv[0] == 0; }
#else
int main(int argc, char **argv) { return argc < 1 || argv == 0 || argv[0] == 0; }
#endif
