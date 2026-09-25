/*
 * Mini Regular Expression Engine in C
 * =====================================
 * 
 * This implementation uses a compiled NFA (Nondeterministic Finite Automaton)
 * representation with backtracking-based matching.
 * 
 * SUPPORTED FEATURES:
 * -------------------
 * - Literal characters: a, b, c, etc.
 * - Metacharacter . (dot): matches any single character
 * - Quantifiers:
 *   * (star): zero or more of the preceding element
 *   + (plus): one or more of the preceding element
 *   ? (question): zero or one of the preceding element
 * - Anchors:
 *   ^ (caret): matches start of string
 *   $ (dollar): matches end of string
 * - Character classes:
 *   [abc]: matches a, b, or c
 *   [a-z]: matches any character from a to z (ranges)
 *   [^abc]: negated class - matches any character except a, b, c
 * - Escape sequences: \., \*, \+, \?, \[, \], \^, \$, \\, \n, \t, \r
 * 
 * ARCHITECTURE:
 * -------------
 * 1. COMPILATION PHASE:
 *    - The regex pattern is parsed and converted into an array of NFA nodes
 *    - Each node represents either a matching condition or a structural element
 *    - The compilation handles character classes by expanding them into bitmaps
 * 
 * 2. MATCHING PHASE:
 *    - Uses recursive backtracking to explore all possible paths through the NFA
 *    - For quantifiers, we try the "greedy" path first (match as much as possible)
 *    - If that fails, we backtrack and try shorter matches
 * 
 * NFA NODE TYPES:
 * ---------------
 * - LITERAL: Match a specific character
 * - ANY: Match any character (.)
 * - CHAR_CLASS: Match any character in a set (uses 256-bit bitmap)
 * - ANCHOR_START: Match beginning of string (^)
 * - ANCHOR_END: Match end of string ($)
 * - MATCH: Successful match (end of pattern)
 * 
 * Each node also has a quantifier field indicating *, +, or ? modifiers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ============================================================================
 * CONSTANTS AND DATA STRUCTURES
 * ============================================================================ */

/* Maximum number of nodes in compiled regex */
#define MAX_NODES 8 /* rax: was 256 */

/* Maximum pattern length */
#define MAX_PATTERN 1024

/* Character class bitmap size (256 bits = 32 bytes for all ASCII chars) */
#define CHAR_CLASS_SIZE 32

/*
 * Node types in the NFA
 * Each type represents a different kind of matching operation
 */
typedef enum {
    NODE_LITERAL,       /* Match a specific character */
    NODE_ANY,           /* Match any character (.) */
    NODE_CHAR_CLASS,    /* Match character in a set [abc] or [^abc] */
    NODE_ANCHOR_START,  /* Match start of string (^) */
    NODE_ANCHOR_END,    /* Match end of string ($) */
    NODE_MATCH          /* Successful match - end of pattern */
} NodeType;

/*
 * Quantifier types
 * These modify how many times a node can match
 */
typedef enum {
    QUANT_NONE,         /* Exactly one match required */
    QUANT_STAR,         /* Zero or more matches (*) */
    QUANT_PLUS,         /* One or more matches (+) */
    QUANT_QUESTION      /* Zero or one match (?) */
} Quantifier;

/*
 * NFA Node structure
 * 
 * This represents a single matching unit in the compiled regex.
 * The char_class field is a 256-bit bitmap where bit N is set if
 * character N should match. This allows O(1) character class checking.
 */
typedef struct {
    NodeType type;                      /* What kind of match this node performs */
    Quantifier quant;                   /* Quantifier modifier (*, +, ?) */
    char literal;                       /* For NODE_LITERAL: the character to match */
    unsigned char char_class[CHAR_CLASS_SIZE];  /* Bitmap for character classes */
    int negated;                        /* For char classes: 1 if negated [^...] */
} Node;

/*
 * Compiled regex structure
 * Contains the array of NFA nodes and metadata
 */
typedef struct {
    Node nodes[MAX_NODES];              /* Array of NFA nodes */
    int node_count;                     /* Number of nodes in the array */
    int valid;                          /* 1 if compilation succeeded, 0 if error */
    char error[256];                    /* Error message if compilation failed */
} Regex;

/*
 * Match result structure
 * Used by regex_search to return match position and length
 */
typedef struct {
    int matched;                        /* 1 if match found, 0 otherwise */
    int start;                          /* Start position of match in string */
    int length;                         /* Length of the match */
} MatchResult;

/* ============================================================================
 * CHARACTER CLASS BITMAP OPERATIONS
 * ============================================================================
 * 
 * We use a 256-bit bitmap to represent character classes efficiently.
 * Each bit corresponds to one ASCII character (0-255).
 * This allows O(1) membership testing instead of linear search.
 */

/*
 * Set a bit in the character class bitmap
 * The bitmap is organized as 32 bytes, with bit (c % 8) of byte (c / 8)
 * representing character c.
 */
static void char_class_set(unsigned char *bitmap, unsigned char c) {
    bitmap[c / 8] |= (1 << (c % 8));
}

/*
 * Test if a character is in the character class
 * Returns non-zero if the bit is set, zero otherwise
 */
static int char_class_test(const unsigned char *bitmap, unsigned char c) {
    return bitmap[c / 8] & (1 << (c % 8));
}

/*
 * Clear all bits in the character class bitmap
 */
static void char_class_clear(unsigned char *bitmap) {
    memset(bitmap, 0, CHAR_CLASS_SIZE);
}

/* ============================================================================
 * REGEX COMPILATION
 * ============================================================================
 * 
 * The compilation phase converts the regex pattern string into an array
 * of NFA nodes. Each node represents one "unit" of matching:
 * 
 * Pattern: "a.*[bc]+$"
 * Compiles to:
 *   Node 0: LITERAL 'a', QUANT_NONE
 *   Node 1: ANY, QUANT_STAR
 *   Node 2: CHAR_CLASS {b,c}, QUANT_PLUS
 *   Node 3: ANCHOR_END, QUANT_NONE
 *   Node 4: MATCH
 * 
 * The compilation handles:
 * 1. Escape sequences (\., \*, etc.)
 * 2. Character class parsing ([abc], [a-z], [^abc])
 * 3. Quantifier attachment (*, +, ?)
 * 4. Anchor recognition (^, $)
 */

/*
 * Parse an escape sequence and return the actual character
 * 
 * Supported escapes:
 * - \n: newline
 * - \t: tab
 * - \r: carriage return
 * - \.: literal dot
 * - \*: literal asterisk
 * - etc.
 * 
 * Parameters:
 *   pattern: the pattern string
 *   pos: pointer to current position (will be advanced past the escape)
 *   c: pointer to store the resulting character
 * 
 * Returns: 1 on success, 0 on error (e.g., \ at end of pattern)
 */
static int parse_escape(const char *pattern, int *pos, char *c) {
    if (pattern[*pos] == '\0') {
        return 0;  /* Error: \ at end of pattern */
    }
    
    char ch = pattern[*pos];
    (*pos)++;
    
    switch (ch) {
        case 'n':  *c = '\n'; break;
        case 't':  *c = '\t'; break;
        case 'r':  *c = '\r'; break;
        case '0':  *c = '\0'; break;
        /* All other characters are literal (handles \., \*, \+, \?, \[, \], \^, \$, \\) */
        default:   *c = ch;   break;
    }
    
    return 1;
}

/*
 * Parse a character class [...]
 * 
 * This function handles:
 * - Simple character lists: [abc]
 * - Character ranges: [a-z], [0-9]
 * - Negation: [^abc]
 * - Escape sequences within classes: [\n\t]
 * - Literal ] as first char: []abc] or [^]abc]
 * - Literal - at start or end: [-abc] or [abc-]
 * 
 * The result is stored as a bitmap in the node's char_class field.
 * 
 * Parameters:
 *   pattern: the pattern string
 *   pos: pointer to current position (should point to char after '[')
 *   node: the node to store the character class in
 *   error: buffer to store error message
 * 
 * Returns: 1 on success, 0 on error
 */
static int parse_char_class(const char *pattern, int *pos, Node *node, char *error) {
    char_class_clear(node->char_class);
    node->type = NODE_CHAR_CLASS;
    node->negated = 0;
    
    /* Check for negation */
    if (pattern[*pos] == '^') {
        node->negated = 1;
        (*pos)++;
    }
    
    /* Handle ] as first character (literal ]) */
    if (pattern[*pos] == ']') {
        char_class_set(node->char_class, ']');
        (*pos)++;
    }
    
    (void)0;  /* Position tracking handled by have_last flag */
    char last_char = 0;  /* Last character added (for range detection) */
    int have_last = 0;   /* Whether we have a valid last_char */
    
    while (pattern[*pos] != '\0' && pattern[*pos] != ']') {
        char c;
        
        if (pattern[*pos] == '\\') {
            /* Handle escape sequence */
            (*pos)++;
            if (!parse_escape(pattern, pos, &c)) {
                snprintf(error, 256, "Incomplete escape sequence in character class");
                return 0;
            }
            char_class_set(node->char_class, (unsigned char)c);
            last_char = c;
            have_last = 1;
        }
        else if (pattern[*pos] == '-' && have_last && pattern[*pos + 1] != '\0' && pattern[*pos + 1] != ']') {
            /* Handle character range like a-z */
            (*pos)++;  /* Skip the - */
            
            char range_end;
            if (pattern[*pos] == '\\') {
                (*pos)++;
                if (!parse_escape(pattern, pos, &range_end)) {
                    snprintf(error, 256, "Incomplete escape sequence in character class range");
                    return 0;
                }
            } else {
                range_end = pattern[*pos];
                (*pos)++;
            }
            
            if ((unsigned char)last_char > (unsigned char)range_end) {
                snprintf(error, 256, "Invalid character range: %c-%c", last_char, range_end);
                return 0;
            }
            
            /* Add all characters in the range */
            for (unsigned char i = (unsigned char)last_char; i <= (unsigned char)range_end; i++) {
                char_class_set(node->char_class, i);
            }
            
            have_last = 0;  /* Range consumed, no last_char for next potential range */
        }
        else {
            /* Regular character */
            c = pattern[*pos];
            (*pos)++;
            char_class_set(node->char_class, (unsigned char)c);
            last_char = c;
            have_last = 1;
        }
        
        /* Continue parsing */
    }
    
    if (pattern[*pos] != ']') {
        snprintf(error, 256, "Unclosed character class");
        return 0;
    }
    
    (*pos)++;  /* Skip closing ] */
    return 1;
}

/*
 * Compile a regex pattern into an NFA
 * 
 * This is the main compilation function. It walks through the pattern
 * character by character, creating nodes for each matching element.
 * 
 * The compilation algorithm:
 * 1. For each character in pattern:
 *    a. If it's a metacharacter (., ^, $, [), create the appropriate node
 *    b. If it's a quantifier (*, +, ?), attach it to the previous node
 *    c. If it's an escape (\), parse the escape and create a literal node
 *    d. Otherwise, create a literal node
 * 2. Add a MATCH node at the end
 * 
 * Parameters:
 *   pattern: the regex pattern string
 * 
 * Returns: a Regex structure (check regex.valid to see if compilation succeeded)
 */
Regex regex_compile(const char *pattern) {
    Regex regex;
    memset(&regex, 0, sizeof(Regex));
    regex.valid = 0;
    
    if (pattern == NULL) {
        snprintf(regex.error, 256, "NULL pattern");
        return regex;
    }
    
    if (strlen(pattern) >= MAX_PATTERN) {
        snprintf(regex.error, 256, "Pattern too long (max %d)", MAX_PATTERN - 1);
        return regex;
    }
    
    int pos = 0;
    int node_idx = 0;
    
    while (pattern[pos] != '\0') {
        if (node_idx >= MAX_NODES - 1) {  /* -1 to leave room for MATCH node */
            snprintf(regex.error, 256, "Pattern too complex (max %d nodes)", MAX_NODES - 1);
            return regex;
        }
        
        Node *node = &regex.nodes[node_idx];
        memset(node, 0, sizeof(Node));
        node->quant = QUANT_NONE;
        
        char c = pattern[pos];
        
        /* Handle metacharacters */
        switch (c) {
            case '.':
                /* Dot: match any character */
                node->type = NODE_ANY;
                pos++;
                break;
                
            case '^':
                /* Caret: anchor to start of string */
                node->type = NODE_ANCHOR_START;
                pos++;
                break;
                
            case '$':
                /* Dollar: anchor to end of string */
                node->type = NODE_ANCHOR_END;
                pos++;
                break;
                
            case '[':
                /* Character class */
                pos++;  /* Skip [ */
                if (!parse_char_class(pattern, &pos, node, regex.error)) {
                    return regex;
                }
                break;
                
            case '*':
            case '+':
            case '?':
                /* Quantifier without preceding element */
                if (node_idx == 0) {
                    snprintf(regex.error, 256, "Quantifier '%c' without preceding element", c);
                    return regex;
                }
                /* Check if previous node already has a quantifier */
                if (regex.nodes[node_idx - 1].quant != QUANT_NONE) {
                    snprintf(regex.error, 256, "Multiple quantifiers not allowed");
                    return regex;
                }
                /* Check if previous node is an anchor (can't quantify anchors) */
                if (regex.nodes[node_idx - 1].type == NODE_ANCHOR_START ||
                    regex.nodes[node_idx - 1].type == NODE_ANCHOR_END) {
                    snprintf(regex.error, 256, "Cannot quantify anchor");
                    return regex;
                }
                /* Attach quantifier to previous node */
                if (c == '*') regex.nodes[node_idx - 1].quant = QUANT_STAR;
                else if (c == '+') regex.nodes[node_idx - 1].quant = QUANT_PLUS;
                else regex.nodes[node_idx - 1].quant = QUANT_QUESTION;
                pos++;
                continue;  /* Don't increment node_idx */
                
            case '\\':
                /* Escape sequence */
                pos++;  /* Skip \ */
                if (!parse_escape(pattern, &pos, &node->literal)) {
                    snprintf(regex.error, 256, "Incomplete escape sequence at end of pattern");
                    return regex;
                }
                node->type = NODE_LITERAL;
                break;
                
            case ']':
                /* Unmatched ] - treat as literal for compatibility */
                node->type = NODE_LITERAL;
                node->literal = c;
                pos++;
                break;
                
            default:
                /* Literal character */
                node->type = NODE_LITERAL;
                node->literal = c;
                pos++;
                break;
        }
        
        node_idx++;
    }
    
    /* Add the final MATCH node */
    regex.nodes[node_idx].type = NODE_MATCH;
    regex.nodes[node_idx].quant = QUANT_NONE;
    regex.node_count = node_idx + 1;
    regex.valid = 1;
    
    return regex;
}

/* ============================================================================
 * REGEX MATCHING
 * ============================================================================
 * 
 * The matching algorithm uses recursive backtracking. For each node in the
 * NFA, we try to match it against the current position in the input string.
 * 
 * For quantifiers, we use a greedy approach:
 * - First, try to match as many times as possible
 * - If that path fails (recursive call returns 0), backtrack and try fewer matches
 * 
 * The backtracking is implicit in the recursion. When a path fails, we return 0,
 * which causes the caller to try the next alternative.
 * 
 * Example matching "a*b" against "aaab":
 * 1. Node 0 (a*): Try to match 3 a's (greedy)
 * 2. Node 1 (b): Try to match at position 3 - found 'b', success!
 * 
 * Example matching "a*b" against "aaac":
 * 1. Node 0 (a*): Try to match 3 a's
 * 2. Node 1 (b): Try to match at position 3 - found 'c', fail
 * 3. Backtrack: Node 0 tries 2 a's
 * 4. Node 1 (b): Try to match at position 2 - found 'a', fail
 * 5. Backtrack: Node 0 tries 1 a
 * 6. Node 1 (b): Try to match at position 1 - found 'a', fail
 * 7. Backtrack: Node 0 tries 0 a's
 * 8. Node 1 (b): Try to match at position 0 - found 'a', fail
 * 9. Overall failure
 */

/*
 * Check if a single node matches a single character
 * 
 * This function does NOT handle quantifiers - it just checks if the node
 * would match the given character.
 * 
 * Parameters:
 *   node: the node to check
 *   c: the character to match against
 * 
 * Returns: 1 if matches, 0 if not
 */
static int node_matches_char(const Node *node, char c) {
    switch (node->type) {
        case NODE_LITERAL:
            return node->literal == c;
            
        case NODE_ANY:
            /* Dot matches any character except newline (traditional behavior) */
            /* Some regex flavors match newline too - we follow POSIX here */
            return c != '\0';  /* We match newlines for simplicity */
            
        case NODE_CHAR_CLASS:
            {
                int in_class = char_class_test(node->char_class, (unsigned char)c);
                /* If negated, we want characters NOT in the class */
                return node->negated ? !in_class : in_class;
            }
            
        default:
            return 0;
    }
}

/*
 * Recursive matching function
 * 
 * This is the core of the backtracking algorithm. It tries to match
 * starting at node_idx in the NFA against position str_pos in the string.
 * 
 * The algorithm:
 * 1. If we've reached the MATCH node, we've successfully matched
 * 2. Handle anchors (^, $) by checking position
 * 3. For quantified nodes, use greedy matching with backtracking:
 *    a. Count how many times we CAN match (up to string length)
 *    b. For *, try all counts from max down to 0
 *    c. For +, try all counts from max down to 1
 *    d. For ?, try counts 1 and 0
 * 4. For non-quantified nodes, just try to match once
 * 
 * Parameters:
 *   regex: the compiled regex
 *   str: the input string
 *   str_len: length of input string
 *   str_pos: current position in input string
 *   node_idx: current node in NFA
 *   start_pos: starting position of the overall match (for ^ anchor)
 *   match_len: pointer to store the length of the match
 * 
 * Returns: 1 if match found, 0 otherwise
 */
static int match_recursive(const Regex *regex, const char *str, int str_len,
                           int str_pos, int node_idx, int start_pos, int *match_len) {
    const Node *node = &regex->nodes[node_idx];
    
    /* If we've reached the MATCH node, we've successfully matched */
    if (node->type == NODE_MATCH) {
        *match_len = str_pos - start_pos;
        return 1;
    }
    
    /* Handle anchors */
    if (node->type == NODE_ANCHOR_START) {
        /* ^ matches only at the start of the string */
        if (str_pos != 0) {
            return 0;
        }
        /* Anchor matched, continue to next node */
        return match_recursive(regex, str, str_len, str_pos, node_idx + 1, start_pos, match_len);
    }
    
    if (node->type == NODE_ANCHOR_END) {
        /* $ matches only at the end of the string */
        if (str_pos != str_len) {
            return 0;
        }
        /* Anchor matched, continue to next node */
        return match_recursive(regex, str, str_len, str_pos, node_idx + 1, start_pos, match_len);
    }
    
    /* Handle quantified nodes with greedy backtracking */
    if (node->quant != QUANT_NONE) {
        /*
         * Greedy matching strategy:
         * First, find the maximum number of characters we can match.
         * Then try from max down to min, recursively checking if the rest matches.
         */
        
        /* Find maximum number of matches possible */
        int max_matches = 0;
        int pos = str_pos;
        while (pos < str_len && node_matches_char(node, str[pos])) {
            max_matches++;
            pos++;
        }
        
        /* Determine minimum matches based on quantifier */
        int min_matches;
        switch (node->quant) {
            case QUANT_STAR:     min_matches = 0; break;
            case QUANT_PLUS:     min_matches = 1; break;
            case QUANT_QUESTION: min_matches = 0; max_matches = (max_matches > 1) ? 1 : max_matches; break;
            default:             min_matches = 1; break;
        }
        
        /*
         * Greedy backtracking: try from max down to min
         * This ensures we match as much as possible while still allowing
         * the rest of the pattern to match
         */
        for (int count = max_matches; count >= min_matches; count--) {
            if (match_recursive(regex, str, str_len, str_pos + count, node_idx + 1, start_pos, match_len)) {
                return 1;
            }
        }
        
        /* No match found with any count */
        return 0;
    }
    
    /* Non-quantified node: must match exactly once */
    if (str_pos >= str_len) {
        /* End of string, can't match */
        return 0;
    }
    
    if (!node_matches_char(node, str[str_pos])) {
        return 0;
    }
    
    /* Character matched, continue to next node */
    return match_recursive(regex, str, str_len, str_pos + 1, node_idx + 1, start_pos, match_len);
}

/*
 * Match a regex against the beginning of a string
 * 
 * This function attempts to match the regex starting at position 0.
 * The entire regex must match, but it doesn't need to consume the entire string.
 * 
 * Parameters:
 *   regex: the compiled regex
 *   str: the input string
 * 
 * Returns: 1 if match, 0 if no match
 */
int regex_match(const Regex *regex, const char *str) {
    if (!regex->valid || str == NULL) {
        return 0;
    }
    
    int match_len;
    return match_recursive(regex, str, strlen(str), 0, 0, 0, &match_len);
}

/*
 * Search for a regex pattern anywhere in a string
 * 
 * This function tries to match the regex starting at each position
 * in the string, returning the first successful match.
 * 
 * Parameters:
 *   regex: the compiled regex
 *   str: the input string
 * 
 * Returns: MatchResult with matched=1 and position info if found,
 *          matched=0 if not found
 */
MatchResult regex_search(const Regex *regex, const char *str) {
    MatchResult result = {0, -1, 0};
    
    if (!regex->valid || str == NULL) {
        return result;
    }
    
    int str_len = strlen(str);
    int match_len;
    
    /* Try matching at each position */
    for (int i = 0; i <= str_len; i++) {
        if (match_recursive(regex, str, str_len, i, 0, i, &match_len)) {
            result.matched = 1;
            result.start = i;
            result.length = match_len;
            return result;
        }
    }
    
    return result;
}

/*
 * Check if a regex matches the entire string (full match)
 * 
 * This is like regex_match but requires the pattern to consume
 * the entire input string.
 * 
 * Parameters:
 *   regex: the compiled regex
 *   str: the input string
 * 
 * Returns: 1 if full match, 0 otherwise
 */
int regex_full_match(const Regex *regex, const char *str) {
    if (!regex->valid || str == NULL) {
        return 0;
    }
    
    int str_len = strlen(str);
    int match_len;
    
    if (match_recursive(regex, str, str_len, 0, 0, 0, &match_len)) {
        return match_len == str_len;
    }
    
    return 0;
}

/* ============================================================================
 * DEBUGGING AND VISUALIZATION
 * ============================================================================ */

/*
 * Print a compiled regex for debugging
 * Shows each node with its type, character/class, and quantifier
 */
void regex_print(const Regex *regex) {
    if (!regex->valid) {
        printf("Invalid regex: %s\n", regex->error);
        return;
    }
    
    printf("Compiled regex (%d nodes):\n", regex->node_count);
    
    for (int i = 0; i < regex->node_count; i++) {
        const Node *node = &regex->nodes[i];
        printf("  [%d] ", i);
        
        switch (node->type) {
            case NODE_LITERAL:
                if (isprint(node->literal)) {
                    printf("LITERAL '%c'", node->literal);
                } else {
                    printf("LITERAL 0x%02x", (unsigned char)node->literal);
                }
                break;
            case NODE_ANY:
                printf("ANY (.)");
                break;
            case NODE_CHAR_CLASS:
                printf("CHAR_CLASS %s[", node->negated ? "^" : "");
                for (int c = 0; c < 256; c++) {
                    if (char_class_test(node->char_class, c)) {
                        if (isprint(c)) {
                            printf("%c", c);
                        } else {
                            printf("\\x%02x", c);
                        }
                    }
                }
                printf("]");
                break;
            case NODE_ANCHOR_START:
                printf("ANCHOR_START (^)");
                break;
            case NODE_ANCHOR_END:
                printf("ANCHOR_END ($)");
                break;
            case NODE_MATCH:
                printf("MATCH");
                break;
        }
        
        switch (node->quant) {
            case QUANT_STAR:     printf(" *"); break;
            case QUANT_PLUS:     printf(" +"); break;
            case QUANT_QUESTION: printf(" ?"); break;
            default: break;
        }
        
        printf("\n");
    }
}

/* ============================================================================
 * TEST FRAMEWORK
 * ============================================================================ */

static int tests_run = 0;
static int tests_passed = 0;

/*
 * Test helper: check if a pattern matches a string (partial match)
 */
static void test_match(const char *pattern, const char *str, int expected, const char *description) {
    tests_run++;
    
    Regex regex = regex_compile(pattern);
    if (!regex.valid) {
        printf("FAIL: %s\n", description);
        printf("      Pattern '%s' failed to compile: %s\n", pattern, regex.error);
        return;
    }
    
    MatchResult result = regex_search(&regex, str);
    int actual = result.matched;
    
    if (actual == expected) {
        printf("PASS: %s\n", description);
        tests_passed++;
    } else {
        printf("FAIL: %s\n", description);
        printf("      Pattern: '%s', String: '%s'\n", pattern, str);
        printf("      Expected: %d, Got: %d\n", expected, actual);
    }
}

/*
 * Test helper: check if a pattern fully matches a string
 */
static void test_full_match(const char *pattern, const char *str, int expected, const char *description) {
    tests_run++;
    
    Regex regex = regex_compile(pattern);
    if (!regex.valid) {
        printf("FAIL: %s\n", description);
        printf("      Pattern '%s' failed to compile: %s\n", pattern, regex.error);
        return;
    }
    
    int actual = regex_full_match(&regex, str);
    
    if (actual == expected) {
        printf("PASS: %s\n", description);
        tests_passed++;
    } else {
        printf("FAIL: %s\n", description);
        printf("      Pattern: '%s', String: '%s'\n", pattern, str);
        printf("      Expected: %d, Got: %d\n", expected, actual);
    }
}

/*
 * Test helper: check search position
 */
static void test_search_pos(const char *pattern, const char *str, int expected_start, int expected_len, const char *description) {
    tests_run++;
    
    Regex regex = regex_compile(pattern);
    if (!regex.valid) {
        printf("FAIL: %s\n", description);
        printf("      Pattern '%s' failed to compile: %s\n", pattern, regex.error);
        return;
    }
    
    MatchResult result = regex_search(&regex, str);
    
    if (result.matched && result.start == expected_start && result.length == expected_len) {
        printf("PASS: %s\n", description);
        tests_passed++;
    } else if (!result.matched && expected_start == -1) {
        printf("PASS: %s\n", description);
        tests_passed++;
    } else {
        printf("FAIL: %s\n", description);
        printf("      Pattern: '%s', String: '%s'\n", pattern, str);
        printf("      Expected: start=%d, len=%d\n", expected_start, expected_len);
        printf("      Got: matched=%d, start=%d, len=%d\n", result.matched, result.start, result.length);
    }
}

/*
 * Test helper: check that a pattern fails to compile
 */
static void test_compile_error(const char *pattern, const char *description) {
    tests_run++;
    
    Regex regex = regex_compile(pattern);
    
    if (!regex.valid) {
        printf("PASS: %s (error: %s)\n", description, regex.error);
        tests_passed++;
    } else {
        printf("FAIL: %s\n", description);
        printf("      Pattern '%s' should have failed to compile\n", pattern);
    }
}

/* ============================================================================
 * MAIN - TEST SUITE
 * ============================================================================ */

int main(void) {
    printf("=======================================================\n");
    printf("Mini Regular Expression Engine - Test Suite\n");
    printf("=======================================================\n\n");
    
    /* ----------------- Literal Characters ----------------- */
    printf("--- Literal Characters ---\n");
    test_match("abc", "abc", 1, "Simple literal match");
    test_match("abc", "xabcy", 1, "Literal found in middle");
    test_match("abc", "ab", 0, "Literal not found (incomplete)");
    test_match("abc", "ABC", 0, "Case sensitive");
    test_full_match("abc", "abc", 1, "Full match literal");
    test_full_match("abc", "abcd", 0, "Full match fails with extra");
    printf("\n");
    
    /* ----------------- Dot (Any Character) ----------------- */
    printf("--- Dot (Any Character) ---\n");
    test_match("a.c", "abc", 1, "Dot matches single char");
    test_match("a.c", "aXc", 1, "Dot matches any char");
    test_match("a.c", "ac", 0, "Dot requires one char");
    test_match("...", "abc", 1, "Multiple dots");
    test_match("...", "ab", 0, "Multiple dots need multiple chars");
    test_full_match("a.c", "abc", 1, "Full match with dot");
    printf("\n");
    
    /* ----------------- Star (Zero or More) ----------------- */
    printf("--- Star (Zero or More) ---\n");
    test_match("ab*c", "ac", 1, "Star matches zero times");
    test_match("ab*c", "abc", 1, "Star matches one time");
    test_match("ab*c", "abbbbc", 1, "Star matches many times");
    test_match("a*", "", 1, "Star matches empty");
    test_match("a*", "aaaa", 1, "Star matches all");
    test_match(".*", "anything", 1, "Dot-star matches anything");
    test_match("a*b*c*", "aabbcc", 1, "Multiple stars");
    test_full_match("a*b", "aaaab", 1, "Star with following literal");
    test_full_match("a*b", "b", 1, "Star matches zero before literal");
    printf("\n");
    
    /* ----------------- Plus (One or More) ----------------- */
    printf("--- Plus (One or More) ---\n");
    test_match("ab+c", "abc", 1, "Plus matches one time");
    test_match("ab+c", "abbbbc", 1, "Plus matches many times");
    test_match("ab+c", "ac", 0, "Plus requires at least one");
    test_match("a+", "a", 1, "Plus matches single");
    test_match("a+", "aaaa", 1, "Plus matches many");
    test_match("a+", "", 0, "Plus doesn't match empty");
    test_full_match("a+b", "aaaab", 1, "Plus with following literal");
    printf("\n");
    
    /* ----------------- Question (Zero or One) ----------------- */
    printf("--- Question (Zero or One) ---\n");
    test_match("ab?c", "ac", 1, "Question matches zero");
    test_match("ab?c", "abc", 1, "Question matches one");
    test_full_match("ab?c", "abbc", 0, "Question doesn't match two");
    test_match("colou?r", "color", 1, "Optional u in color");
    test_match("colou?r", "colour", 1, "Optional u in colour");
    test_full_match("a?b?c?", "", 1, "All optional matches empty");
    test_full_match("a?b?c?", "abc", 1, "All optional matches full");
    printf("\n");
    
    /* ----------------- Anchor Start (^) ----------------- */
    printf("--- Anchor Start (^) ---\n");
    test_match("^abc", "abc", 1, "Caret at start");
    test_match("^abc", "abcdef", 1, "Caret at start with more");
    test_match("^abc", "xabc", 0, "Caret fails if not at start");
    test_match("^", "anything", 1, "Just caret matches");
    test_match("^a*", "aaaa", 1, "Caret with star");
    test_full_match("^abc$", "abc", 1, "Caret and dollar");
    printf("\n");
    
    /* ----------------- Anchor End ($) ----------------- */
    printf("--- Anchor End ($) ---\n");
    test_match("abc$", "abc", 1, "Dollar at end");
    test_match("abc$", "xyzabc", 1, "Dollar at end with prefix");
    test_match("abc$", "abcx", 0, "Dollar fails if not at end");
    test_match("$", "", 1, "Just dollar matches empty");
    test_match("a*$", "aaaa", 1, "Star with dollar");
    test_full_match("^$", "", 1, "Empty pattern matches empty string");
    printf("\n");
    
    /* ----------------- Character Classes [abc] ----------------- */
    printf("--- Character Classes ---\n");
    test_match("[abc]", "a", 1, "Char class matches first");
    test_match("[abc]", "b", 1, "Char class matches second");
    test_match("[abc]", "c", 1, "Char class matches third");
    test_match("[abc]", "d", 0, "Char class doesn't match other");
    test_match("[abc]+", "aabbcc", 1, "Char class with plus");
    test_match("[abc]*", "", 1, "Char class with star empty");
    test_full_match("[abc][def]", "ad", 1, "Multiple char classes");
    printf("\n");
    
    /* ----------------- Character Ranges [a-z] ----------------- */
    printf("--- Character Ranges ---\n");
    test_match("[a-z]", "m", 1, "Range matches middle");
    test_match("[a-z]", "a", 1, "Range matches start");
    test_match("[a-z]", "z", 1, "Range matches end");
    test_match("[a-z]", "A", 0, "Range is case sensitive");
    test_match("[0-9]", "5", 1, "Digit range");
    test_match("[0-9]", "a", 0, "Digit range rejects letter");
    test_match("[a-zA-Z]", "M", 1, "Combined ranges uppercase");
    test_match("[a-zA-Z]", "m", 1, "Combined ranges lowercase");
    test_match("[a-zA-Z0-9]", "5", 1, "Alphanumeric range");
    test_full_match("[a-z]+", "hello", 1, "Range with quantifier");
    printf("\n");
    
    /* ----------------- Negated Character Classes [^abc] ----------------- */
    printf("--- Negated Character Classes ---\n");
    test_match("[^abc]", "d", 1, "Negated class matches other");
    test_match("[^abc]", "a", 0, "Negated class rejects member");
    test_match("[^abc]", "b", 0, "Negated class rejects member 2");
    test_match("[^0-9]", "a", 1, "Negated range matches non-digit");
    test_match("[^0-9]", "5", 0, "Negated range rejects digit");
    test_match("[^a-z]+", "ABC123", 1, "Negated range with plus");
    test_full_match("[^abc]*", "xyz", 1, "Negated class star");
    printf("\n");
    
    /* ----------------- Escape Sequences ----------------- */
    printf("--- Escape Sequences ---\n");
    test_match("\\.", ".", 1, "Escaped dot matches literal");
    test_match("\\.", "a", 0, "Escaped dot doesn't match other");
    test_match("\\*", "*", 1, "Escaped star matches literal");
    test_match("\\+", "+", 1, "Escaped plus matches literal");
    test_match("\\?", "?", 1, "Escaped question matches literal");
    test_match("\\[", "[", 1, "Escaped bracket matches literal");
    test_match("\\]", "]", 1, "Escaped close bracket matches literal");
    test_match("\\^", "^", 1, "Escaped caret matches literal");
    test_match("\\$", "$", 1, "Escaped dollar matches literal");
    test_match("\\\\", "\\", 1, "Escaped backslash matches literal");
    test_match("a\\.b", "a.b", 1, "Escaped dot in context");
    test_match("a\\.b", "aXb", 0, "Escaped dot doesn't match any");
    test_full_match("\\n", "\n", 1, "Escaped n matches newline");
    test_full_match("\\t", "\t", 1, "Escaped t matches tab");
    printf("\n");
    
    /* ----------------- Search Position Tests ----------------- */
    printf("--- Search Position ---\n");
    test_search_pos("abc", "xxxabcyyy", 3, 3, "Find abc in middle");
    test_search_pos("a+", "bbbaaaccc", 3, 3, "Find a+ greedy");
    test_search_pos("^abc", "abcdef", 0, 3, "Find ^abc at start");
    test_search_pos("def$", "abcdef", 3, 3, "Find def$ at end");
    test_search_pos("[0-9]+", "abc123def", 3, 3, "Find digits in string");
    test_search_pos("xyz", "abc", -1, 0, "Not found returns -1");
    printf("\n");
    
    /* ----------------- Complex Patterns ----------------- */
    printf("--- Complex Patterns ---\n");
    test_match("^[a-zA-Z_][a-zA-Z0-9_]*$", "validIdentifier", 1, "C identifier valid");
    test_match("^[a-zA-Z_][a-zA-Z0-9_]*$", "_private", 1, "C identifier underscore");
    test_match("^[a-zA-Z_][a-zA-Z0-9_]*$", "123invalid", 0, "C identifier invalid start");
    test_match("[0-9]+\\.[0-9]+", "3.14", 1, "Decimal number");
    test_match("[0-9]+\\.[0-9]+", "3", 0, "Decimal needs dot");
    test_match("a.*b.*c", "aXXXbYYYc", 1, "Wildcards in middle");
    test_match("^.*$", "anything goes here", 1, "Match entire line");
    test_full_match("[a-z]+@[a-z]+\\.[a-z]+", "test@example.com", 1, "Simple email pattern");
    printf("\n");
    
    /* ----------------- Edge Cases ----------------- */
    printf("--- Edge Cases ---\n");
    test_match("", "", 1, "Empty pattern matches empty string");
    test_match("", "abc", 1, "Empty pattern matches any string");
    test_match("a", "", 0, "Non-empty pattern fails on empty string");
    test_match("[]a]", "]", 1, "Bracket as first char in class");
    test_match("[]a]", "a", 1, "Bracket as first char in class 2");
    test_match("[a-]", "-", 1, "Hyphen at end of class");
    test_match("[a-]", "a", 1, "Hyphen at end of class 2");
    test_match("[-a]", "-", 1, "Hyphen at start of class");
    test_compile_error("a**", "Double star is compile error");
    printf("\n");
    
    /* ----------------- Error Cases ----------------- */
    printf("--- Error Cases ---\n");
    test_compile_error("*", "Star without preceding element");
    test_compile_error("+", "Plus without preceding element");
    test_compile_error("?", "Question without preceding element");
    test_compile_error("[abc", "Unclosed character class");
    test_compile_error("\\", "Trailing backslash");
    test_compile_error("a++", "Double quantifier");
    test_compile_error("^*", "Quantified anchor start");
    test_compile_error("$*", "Quantified anchor end");
    test_compile_error("[z-a]", "Invalid range (reversed)");
    printf("\n");
    
    /* ----------------- Greedy Backtracking Tests ----------------- */
    printf("--- Greedy Backtracking ---\n");
    test_full_match("a*a", "aaa", 1, "Backtracking: a*a on aaa");
    test_full_match(".*x", "abcx", 1, "Backtracking: .*x on abcx");
    test_full_match("a*aa", "aaa", 1, "Backtracking: a*aa on aaa");
    test_full_match(".*.*.*x", "abcx", 1, "Multiple greedy wildcards");
    test_full_match("[ab]*b", "aabb", 1, "Backtracking with char class");
    printf("\n");
    
    /* ----------------- Summary ----------------- */
    printf("=======================================================\n");
    printf("Test Results: %d/%d passed", tests_passed, tests_run);
    if (tests_passed == tests_run) {
        printf(" - ALL TESTS PASSED!\n");
    } else {
        printf(" - %d FAILED\n", tests_run - tests_passed);
    }
    printf("=======================================================\n");
    
    /* Demo: Print a compiled regex */
    printf("\nDemo: Compiled regex structure for \"^[a-z]+[0-9]*$\":\n");
    Regex demo = regex_compile("^[a-z]+[0-9]*$");
    regex_print(&demo);
    
    return (tests_passed == tests_run) ? 0 : 1;
}
