/* Exact declaration excerpts, Microsoft win32metadata WinSDK winnt.h.
 * Retrieval: 2026-09-27. Source URL and fragment hash in sources.json.
 * Source revision: unknown (mutable main branch). Not a standalone header.
 * THREAD_ALL_ACCESS branches retain source ordering; modern Windows uses
 * the first branch (0xFFFF), XP compatibility the second branch (0x03FF).
 */
#define MAXCHAR     0x7f        
#define MAXIMUM_WAIT_OBJECTS 64     // Maximum number of wait objects
#define MAXIMUM_SUSPEND_COUNT MAXCHAR // Maximum times thread can be suspended
#define SYNCHRONIZE                      (0x00100000L)
#define STANDARD_RIGHTS_REQUIRED         (0x000F0000L)
#define THREAD_TERMINATE                 (0x0001)  
#define THREAD_SUSPEND_RESUME            (0x0002)  
#define THREAD_SET_CONTEXT               (0x0010)  
#define THREAD_QUERY_INFORMATION         (0x0040)  
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)  // winnt
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0x3FF)
