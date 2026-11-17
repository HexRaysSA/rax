/* No allocation: exact pinned frontend source type-size boundary. */
typedef unsigned char LargestSourceObject[2305843009213693951ULL];
static_assert(sizeof(LargestSourceObject) == 2305843009213693951ULL);
#ifdef EXPECT_REJECTION
typedef unsigned char TooLargeSourceObject[2305843009213693952ULL];
#endif
