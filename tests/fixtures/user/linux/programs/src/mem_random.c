/*
 * Random/Indirect Memory Access Patterns
 *
 * Tests pointer chasing and irregular access patterns.
 * Exercises memory latency and TLB behavior.
 *
 * Features exercised:
 *   - Pointer chasing (linked structures)
 *   - Index-based indirection
 *   - Hash table access patterns
 *   - Tree traversal patterns
 */

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

#define ARRAY_SIZE 1024 /* rax: was 4096 */
#define HASH_SIZE 1024

volatile int64_t sink;

/* Linked list node */
typedef struct Node {
    int32_t value;
    struct Node *next;
} Node;

/* Tree node */
typedef struct TreeNode {
    int32_t value;
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;

/* Arrays for indirect access */
static int32_t data_array[ARRAY_SIZE];
static size_t index_array[ARRAY_SIZE];
static size_t permutation[ARRAY_SIZE];

/* Linked list storage */
static Node nodes[ARRAY_SIZE];
static Node *list_head;

/* Tree storage */
static TreeNode tree_nodes[ARRAY_SIZE];
static TreeNode *tree_root;

/* Simple hash table */
typedef struct {
    int32_t key;
    int32_t value;
    int32_t next_idx; /* -1 if none */
} HashEntry;

static HashEntry hash_table[HASH_SIZE];
static int32_t hash_buckets[HASH_SIZE];

/* Simple PRNG for reproducible "random" access */
static uint32_t prng_state = 12345;

__attribute__((noinline))
uint32_t prng_next(void) {
    prng_state = prng_state * 1103515245 + 12345;
    return prng_state;
}

/* Pointer chasing through linked list */
__attribute__((noinline))
int64_t pointer_chase_list(Node *head, int steps) {
    int64_t sum = 0;
    Node *current = head;
    for (int i = 0; i < steps && current != NULL; i++) {
        sum += current->value;
        current = current->next;
    }
    return sum;
}

/* Index-based indirect access */
__attribute__((noinline))
int64_t indirect_access(const int32_t *data, const size_t *indices, size_t count) {
    int64_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        sum += data[indices[i]];
    }
    return sum;
}

/* Double indirection */
__attribute__((noinline))
int64_t double_indirect(const int32_t *data, const size_t *idx1, const size_t *idx2, size_t count) {
    int64_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        sum += data[idx1[idx2[i]]];
    }
    return sum;
}

/* Chained index chasing (like pointer chasing but with indices) */
__attribute__((noinline))
int64_t index_chase(const int32_t *data, const size_t *next, size_t start, int steps) {
    int64_t sum = 0;
    size_t idx = start;
    for (int i = 0; i < steps; i++) {
        sum += data[idx];
        idx = next[idx];
        if (idx >= ARRAY_SIZE) break;
    }
    return sum;
}

/* Permutation access */
__attribute__((noinline))
int64_t permuted_access(const int32_t *data, const size_t *perm, size_t len) {
    int64_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[perm[i]];
    }
    return sum;
}

/* Permutation write (scatter) */
__attribute__((noinline))
void permuted_write(int32_t *data, const size_t *perm, const int32_t *values, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[perm[i]] = values[i];
    }
}

/* Hash table lookup */
__attribute__((noinline))
uint32_t hash_function(int32_t key) {
    uint32_t h = (uint32_t)key;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h % HASH_SIZE;
}

__attribute__((noinline))
int32_t hash_lookup(int32_t key) {
    uint32_t bucket = hash_function(key);
    int32_t idx = hash_buckets[bucket];

    while (idx >= 0) {
        if (hash_table[idx].key == key) {
            return hash_table[idx].value;
        }
        idx = hash_table[idx].next_idx;
    }

    return -1; /* Not found */
}

/* Tree traversal - preorder */
__attribute__((noinline))
int64_t tree_preorder(TreeNode *node) {
    if (node == NULL) return 0;
    return node->value + tree_preorder(node->left) + tree_preorder(node->right);
}

/* Tree traversal - iterative with stack simulation */
__attribute__((noinline))
int64_t tree_iterative(TreeNode *root) {
    if (root == NULL) return 0;

    TreeNode *stack[64];
    int sp = 0;
    int64_t sum = 0;

    stack[sp++] = root;
    while (sp > 0) {
        TreeNode *node = stack[--sp];
        sum += node->value;
        if (node->right && sp < 63) stack[sp++] = node->right;
        if (node->left && sp < 63) stack[sp++] = node->left;
    }
    return sum;
}

/* Binary search tree lookup */
__attribute__((noinline))
TreeNode *bst_lookup(TreeNode *root, int32_t key) {
    while (root != NULL) {
        if (key < root->value) {
            root = root->left;
        } else if (key > root->value) {
            root = root->right;
        } else {
            return root;
        }
    }
    return NULL;
}

/* Random access pattern */
__attribute__((noinline))
int64_t random_access(const int32_t *data, size_t len, int accesses) {
    int64_t sum = 0;
    for (int i = 0; i < accesses; i++) {
        size_t idx = prng_next() % len;
        sum += data[idx];
    }
    return sum;
}

/* Dependent random access */
__attribute__((noinline))
int64_t dependent_random(const int32_t *data, size_t len, int accesses) {
    int64_t sum = 0;
    size_t idx = 0;
    for (int i = 0; i < accesses; i++) {
        sum += data[idx];
        idx = ((size_t)data[idx] * 7 + 13) % len;
    }
    return sum;
}

/* Strided random access (random within blocks) */
__attribute__((noinline))
int64_t strided_random(const int32_t *data, size_t len, size_t block_size, int accesses) {
    int64_t sum = 0;
    for (int i = 0; i < accesses; i++) {
        size_t block = (prng_next() % (len / block_size)) * block_size;
        size_t offset = prng_next() % block_size;
        sum += data[block + offset];
    }
    return sum;
}

/* Initialize data structures */
void init_structures(void) {
    /* Initialize data and indices */
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        data_array[i] = (int32_t)i;
        index_array[i] = (i * 7 + 13) % ARRAY_SIZE;
        permutation[i] = i;
    }

    /* Fisher-Yates shuffle for permutation */
    prng_state = 42;
    for (size_t i = ARRAY_SIZE - 1; i > 0; i--) {
        size_t j = prng_next() % (i + 1);
        size_t tmp = permutation[i];
        permutation[i] = permutation[j];
        permutation[j] = tmp;
    }

    /* Build linked list (randomized order) */
    list_head = &nodes[permutation[0]];
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        nodes[permutation[i]].value = (int32_t)permutation[i];
        if (i + 1 < ARRAY_SIZE) {
            nodes[permutation[i]].next = &nodes[permutation[i + 1]];
        } else {
            nodes[permutation[i]].next = NULL;
        }
    }

    /* Build simple binary tree */
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        tree_nodes[i].value = (int32_t)i;
        tree_nodes[i].left = NULL;
        tree_nodes[i].right = NULL;
    }

    /* Connect as balanced-ish tree */
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        size_t left = 2 * i + 1;
        size_t right = 2 * i + 2;
        if (left < ARRAY_SIZE) tree_nodes[i].left = &tree_nodes[left];
        if (right < ARRAY_SIZE) tree_nodes[i].right = &tree_nodes[right];
    }
    tree_root = &tree_nodes[0];

    /* Initialize hash table */
    for (size_t i = 0; i < HASH_SIZE; i++) {
        hash_buckets[i] = -1;
    }

    for (size_t i = 0; i < HASH_SIZE; i++) {
        int32_t key = (int32_t)(i * 17);
        uint32_t bucket = hash_function(key);

        hash_table[i].key = key;
        hash_table[i].value = (int32_t)(i * 100);
        hash_table[i].next_idx = hash_buckets[bucket];
        hash_buckets[bucket] = (int32_t)i;
    }
}

int main(void) {
    int64_t result = 0;

    init_structures();

    int32_t values[ARRAY_SIZE];
    for (size_t i = 0; i < ARRAY_SIZE; i++) {
        values[i] = (int32_t)(i * 3);
    }

    for (int iter = 0; iter < 3; iter++) { /* rax: was 2000 */
        /* Pointer chasing */
        result += pointer_chase_list(list_head, 1000);

        /* Indirect access */
        result += indirect_access(data_array, index_array, ARRAY_SIZE);

        /* Double indirection */
        result += double_indirect(data_array, index_array, permutation, 1024);

        /* Index chasing */
        result += index_chase(data_array, index_array, iter % ARRAY_SIZE, 500);

        /* Permuted access */
        result += permuted_access(data_array, permutation, ARRAY_SIZE);

        /* Permuted write */
        if (iter % 100 == 0) {
            permuted_write(data_array, permutation, values, ARRAY_SIZE);
        }

        /* Hash table lookups */
        for (int i = 0; i < 100; i++) {
            int32_t key = (int32_t)((iter + i) * 17) % (HASH_SIZE * 17);
            result += hash_lookup(key);
        }

        /* Tree traversal */
        if (iter % 50 == 0) {
            result += tree_preorder(tree_root);
        }
        result += tree_iterative(tree_root);

        /* BST lookups */
        for (int i = 0; i < 20; i++) {
            TreeNode *found = bst_lookup(tree_root, (iter + i) % ARRAY_SIZE);
            if (found) result += found->value;
        }

        /* Random access */
        prng_state = (uint32_t)iter;
        result += random_access(data_array, ARRAY_SIZE, 500);

        /* Dependent random */
        result += dependent_random(data_array, ARRAY_SIZE, 200);

        /* Strided random */
        result += strided_random(data_array, ARRAY_SIZE, 64, 300);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", (int64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
