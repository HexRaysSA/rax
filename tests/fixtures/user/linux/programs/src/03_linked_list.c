/**
 * =============================================================================
 * Comprehensive Singly Linked List Implementation in C
 * =============================================================================
 * 
 * A singly linked list is a linear data structure where each element (node)
 * contains data and a pointer to the next node in the sequence. Unlike arrays,
 * linked lists don't require contiguous memory allocation, making insertions
 * and deletions more efficient (O(1) at known positions vs O(n) for arrays).
 * 
 * Trade-offs:
 * - Pros: Dynamic size, efficient insertions/deletions, no memory waste
 * - Cons: No random access (must traverse), extra memory for pointers,
 *         poor cache locality compared to arrays
 * 
 * Time Complexities:
 * - Access:    O(n) - must traverse from head
 * - Search:    O(n) - must traverse to find element
 * - Insertion: O(1) at head, O(n) at tail or position (due to traversal)
 * - Deletion:  O(1) at head, O(n) at tail or position (due to traversal)
 * 
 * Memory Management:
 * - Each node is dynamically allocated with malloc()
 * - Must be explicitly freed to prevent memory leaks
 * - This implementation tracks a head pointer; NULL indicates empty list
 * 
 * Author: ARM Assembly Learning Project
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* =============================================================================
 * Data Structure Definition
 * =============================================================================
 * 
 * The Node structure is the fundamental building block of our linked list.
 * Each node contains:
 * - data: The integer value stored in this node
 * - next: A pointer to the next node (NULL if this is the last node)
 * 
 * Memory layout (on 64-bit system):
 * +--------+--------+
 * |  data  |  next  |
 * | 4 bytes| 8 bytes|
 * +--------+--------+
 * (May include padding for alignment)
 */
typedef struct Node {
    int data;           /* The integer value stored in this node */
    struct Node *next;  /* Pointer to the next node in the list */
} Node;

/* =============================================================================
 * Function Prototypes
 * =============================================================================
 * Forward declarations allow functions to be defined in any order and
 * enable mutual recursion if needed.
 */
Node *create_node(int data);
Node *insert_head(Node *head, int data);
Node *insert_tail(Node *head, int data);
Node *insert_at_position(Node *head, int data, int position);
Node *delete_node(Node *head, int data);
Node *delete_at_position(Node *head, int position);
Node *find_node(Node *head, int data);
int get_length(Node *head);
Node *reverse_list(Node *head);
Node *reverse_list_recursive(Node *head);
void print_list(Node *head);
void print_list_detailed(Node *head);
void free_list(Node *head);

/* =============================================================================
 * create_node - Allocate and initialize a new node
 * =============================================================================
 * 
 * This function is the foundation for all insertion operations. It:
 * 1. Allocates memory for a new Node structure on the heap
 * 2. Initializes the data field with the provided value
 * 3. Sets the next pointer to NULL (isolated node)
 * 
 * Parameters:
 *   data - The integer value to store in the new node
 * 
 * Returns:
 *   Pointer to the newly created node, or NULL if allocation fails
 * 
 * Memory: Allocates sizeof(Node) bytes on the heap
 * 
 * Note: The caller is responsible for eventually freeing this memory,
 *       either directly or through free_list()
 */
Node *create_node(int data) {
    /* Allocate memory for the new node */
    Node *new_node = (Node *)malloc(sizeof(Node));
    
    /* Check if memory allocation succeeded */
    if (new_node == NULL) {
        fprintf(stderr, "Error: Memory allocation failed in create_node()\n");
        return NULL;
    }
    
    /* Initialize the node's fields */
    new_node->data = data;  /* Store the provided data value */
    new_node->next = NULL;  /* New node doesn't point to anything yet */
    
    return new_node;
}

/* =============================================================================
 * insert_head - Insert a new node at the beginning of the list
 * =============================================================================
 * 
 * This is the most efficient insertion operation (O(1)) because we don't
 * need to traverse the list. The new node becomes the new head.
 * 
 * Before: head -> [A] -> [B] -> [C] -> NULL
 * After:  head -> [NEW] -> [A] -> [B] -> [C] -> NULL
 * 
 * Parameters:
 *   head - Pointer to the current head of the list (can be NULL for empty list)
 *   data - The integer value to store in the new node
 * 
 * Returns:
 *   Pointer to the new head of the list (the newly inserted node)
 *   Returns NULL only if memory allocation fails
 * 
 * Edge cases handled:
 *   - Empty list (head == NULL): New node becomes the only node
 *   - Memory allocation failure: Returns NULL, original list unchanged
 */
Node *insert_head(Node *head, int data) {
    /* Create a new node with the given data */
    Node *new_node = create_node(data);
    
    /* Handle allocation failure */
    if (new_node == NULL) {
        return head;  /* Return original list unchanged */
    }
    
    /* Link new node to the current head (works even if head is NULL) */
    new_node->next = head;
    
    /* New node is now the head of the list */
    return new_node;
}

/* =============================================================================
 * insert_tail - Insert a new node at the end of the list
 * =============================================================================
 * 
 * This operation requires O(n) time because we must traverse the entire
 * list to find the last node. Could be optimized to O(1) by maintaining
 * a tail pointer, but that adds complexity.
 * 
 * Before: head -> [A] -> [B] -> [C] -> NULL
 * After:  head -> [A] -> [B] -> [C] -> [NEW] -> NULL
 * 
 * Parameters:
 *   head - Pointer to the current head of the list (can be NULL)
 *   data - The integer value to store in the new node
 * 
 * Returns:
 *   Pointer to the head of the list (unchanged unless list was empty)
 * 
 * Edge cases handled:
 *   - Empty list: New node becomes the head
 *   - Single node list: New node linked after the head
 */
Node *insert_tail(Node *head, int data) {
    /* Create a new node with the given data */
    Node *new_node = create_node(data);
    
    /* Handle allocation failure */
    if (new_node == NULL) {
        return head;
    }
    
    /* Special case: empty list - new node becomes the head */
    if (head == NULL) {
        return new_node;
    }
    
    /* Traverse to find the last node */
    Node *current = head;
    while (current->next != NULL) {
        current = current->next;
    }
    
    /* Link the last node to our new node */
    current->next = new_node;
    
    /* Head remains unchanged */
    return head;
}

/* =============================================================================
 * insert_at_position - Insert a new node at a specific position
 * =============================================================================
 * 
 * Inserts a node at the given position (0-indexed). Position 0 means
 * insert at head, position equal to length means insert at tail.
 * 
 * Before (insert at position 2):
 *   head -> [A] -> [B] -> [C] -> [D] -> NULL
 *            0      1      2      3
 * 
 * After:
 *   head -> [A] -> [B] -> [NEW] -> [C] -> [D] -> NULL
 *            0      1       2       3      4
 * 
 * Parameters:
 *   head     - Pointer to the current head of the list
 *   data     - The integer value to store in the new node
 *   position - Zero-based index where the new node should be inserted
 * 
 * Returns:
 *   Pointer to the head of the list (may change if position is 0)
 * 
 * Edge cases handled:
 *   - position == 0: Equivalent to insert_head
 *   - position > length: Inserts at the end (graceful handling)
 *   - Negative position: Treated as 0 (insert at head)
 */
Node *insert_at_position(Node *head, int data, int position) {
    /* Handle negative positions by inserting at head */
    if (position <= 0) {
        return insert_head(head, data);
    }
    
    /* Handle empty list */
    if (head == NULL) {
        return create_node(data);
    }
    
    /* Create the new node */
    Node *new_node = create_node(data);
    if (new_node == NULL) {
        return head;
    }
    
    /* Traverse to the node just before the desired position */
    Node *current = head;
    int current_position = 0;
    
    /* Stop when we reach position-1 or the end of the list */
    while (current->next != NULL && current_position < position - 1) {
        current = current->next;
        current_position++;
    }
    
    /* Insert the new node after current */
    new_node->next = current->next;  /* Link new node to the rest of the list */
    current->next = new_node;        /* Link previous node to new node */
    
    return head;
}

/* =============================================================================
 * delete_node - Delete the first node containing the specified value
 * =============================================================================
 * 
 * Searches for the first node with matching data and removes it from the list.
 * The memory for the deleted node is freed.
 * 
 * Before (delete value 20):
 *   head -> [10] -> [20] -> [30] -> NULL
 * 
 * After:
 *   head -> [10] -> [30] -> NULL
 *   (Node with 20 is freed)
 * 
 * Parameters:
 *   head - Pointer to the current head of the list
 *   data - The value to search for and delete
 * 
 * Returns:
 *   Pointer to the head of the list (may change if head node is deleted)
 * 
 * Edge cases handled:
 *   - Empty list: Returns NULL
 *   - Value not found: Returns original list unchanged
 *   - Deleting head node: Returns new head
 *   - Deleting last node: Returns NULL (empty list)
 */
Node *delete_node(Node *head, int data) {
    /* Empty list - nothing to delete */
    if (head == NULL) {
        printf("Warning: Cannot delete from empty list\n");
        return NULL;
    }
    
    /* Special case: deleting the head node */
    if (head->data == data) {
        Node *new_head = head->next;  /* Save reference to second node */
        free(head);                    /* Free the old head */
        return new_head;               /* Return new head (may be NULL) */
    }
    
    /* Search for the node to delete (need pointer to previous node) */
    Node *current = head;
    while (current->next != NULL && current->next->data != data) {
        current = current->next;
    }
    
    /* Check if we found the node */
    if (current->next == NULL) {
        printf("Warning: Value %d not found in list\n", data);
        return head;  /* Value not found, return unchanged list */
    }
    
    /* Remove the node from the list */
    Node *node_to_delete = current->next;
    current->next = node_to_delete->next;  /* Bypass the node to delete */
    free(node_to_delete);                   /* Free the memory */
    
    return head;
}

/* =============================================================================
 * delete_at_position - Delete node at a specific position
 * =============================================================================
 * 
 * Removes the node at the given position (0-indexed).
 * 
 * Parameters:
 *   head     - Pointer to the current head of the list
 *   position - Zero-based index of the node to delete
 * 
 * Returns:
 *   Pointer to the head of the list (may change if position is 0)
 * 
 * Edge cases handled:
 *   - Empty list: Returns NULL
 *   - Invalid position: Returns original list unchanged
 *   - position == 0: Deletes head node
 */
Node *delete_at_position(Node *head, int position) {
    /* Empty list or invalid position */
    if (head == NULL) {
        printf("Warning: Cannot delete from empty list\n");
        return NULL;
    }
    
    if (position < 0) {
        printf("Warning: Invalid position %d\n", position);
        return head;
    }
    
    /* Special case: deleting head (position 0) */
    if (position == 0) {
        Node *new_head = head->next;
        free(head);
        return new_head;
    }
    
    /* Traverse to the node just before the one to delete */
    Node *current = head;
    int current_position = 0;
    
    while (current->next != NULL && current_position < position - 1) {
        current = current->next;
        current_position++;
    }
    
    /* Check if position is valid */
    if (current->next == NULL) {
        printf("Warning: Position %d is out of bounds\n", position);
        return head;
    }
    
    /* Remove the node */
    Node *node_to_delete = current->next;
    current->next = node_to_delete->next;
    free(node_to_delete);
    
    return head;
}

/* =============================================================================
 * find_node - Search for a node containing the specified value
 * =============================================================================
 * 
 * Performs a linear search through the list to find the first node
 * containing the specified value.
 * 
 * Parameters:
 *   head - Pointer to the head of the list
 *   data - The value to search for
 * 
 * Returns:
 *   Pointer to the first node containing the value, or NULL if not found
 * 
 * Note: This returns a pointer to the actual node in the list, not a copy.
 *       Modifying the returned node will modify the list.
 */
Node *find_node(Node *head, int data) {
    Node *current = head;
    
    /* Traverse the list searching for the value */
    while (current != NULL) {
        if (current->data == data) {
            return current;  /* Found it! */
        }
        current = current->next;
    }
    
    /* Value not found in the list */
    return NULL;
}

/* =============================================================================
 * get_length - Count the number of nodes in the list
 * =============================================================================
 * 
 * Traverses the entire list and counts the nodes.
 * 
 * Parameters:
 *   head - Pointer to the head of the list
 * 
 * Returns:
 *   The number of nodes in the list (0 for empty list)
 */
int get_length(Node *head) {
    int count = 0;
    Node *current = head;
    
    while (current != NULL) {
        count++;
        current = current->next;
    }
    
    return count;
}

/* =============================================================================
 * reverse_list - Reverse the list in place (iterative approach)
 * =============================================================================
 * 
 * Reverses the direction of all pointers in the list. Uses three pointers
 * to track the previous, current, and next nodes as we traverse.
 * 
 * Before: head -> [A] -> [B] -> [C] -> NULL
 * After:  head -> [C] -> [B] -> [A] -> NULL
 * 
 * Algorithm (at each step):
 * 1. Save the next node (so we don't lose it)
 * 2. Point current node backward to previous
 * 3. Move previous and current forward
 * 
 * Visual representation of one iteration:
 *   prev    current    next
 *    |        |         |
 *   [A]  <-  [B]  ->   [C] -> NULL
 *            ^
 *            reverse this pointer
 * 
 * Parameters:
 *   head - Pointer to the current head of the list
 * 
 * Returns:
 *   Pointer to the new head (was the tail)
 * 
 * Time: O(n), Space: O(1)
 */
Node *reverse_list(Node *head) {
    Node *prev = NULL;      /* Previous node (starts as NULL) */
    Node *current = head;   /* Current node being processed */
    Node *next = NULL;      /* Next node (saved before we change pointer) */
    
    while (current != NULL) {
        /* Step 1: Save the next node before we overwrite the pointer */
        next = current->next;
        
        /* Step 2: Reverse the pointer - point current back to previous */
        current->next = prev;
        
        /* Step 3: Move prev and current one step forward */
        prev = current;
        current = next;
    }
    
    /* prev now points to the last node (new head) */
    return prev;
}

/* =============================================================================
 * reverse_list_recursive - Reverse the list using recursion
 * =============================================================================
 * 
 * An alternative recursive implementation of list reversal.
 * 
 * How it works:
 * 1. Base case: empty list or single node - return as is
 * 2. Recurse to the end of the list
 * 3. On the way back, reverse each pointer
 * 
 * Example with [1] -> [2] -> [3] -> NULL:
 * 
 * Call stack going down:
 *   reverse([1]) -> reverse([2]) -> reverse([3])
 *                                   returns [3] (base case)
 * 
 * Coming back up:
 *   At [2]: [2]->next is [3], so [3]->next = [2], [2]->next = NULL
 *           Now: [3] -> [2] -> NULL
 *   At [1]: [1]->next is [2], so [2]->next = [1], [1]->next = NULL
 *           Now: [3] -> [2] -> [1] -> NULL
 * 
 * Parameters:
 *   head - Pointer to the current head of the list
 * 
 * Returns:
 *   Pointer to the new head (was the tail)
 * 
 * Time: O(n), Space: O(n) due to call stack
 */
Node *reverse_list_recursive(Node *head) {
    /* Base case: empty list or single node */
    if (head == NULL || head->next == NULL) {
        return head;
    }
    
    /* Recursively reverse the rest of the list */
    Node *new_head = reverse_list_recursive(head->next);
    
    /* head->next is now the last node of the reversed sublist */
    /* Make it point back to head */
    head->next->next = head;
    
    /* head is now the last node, so it should point to NULL */
    head->next = NULL;
    
    /* Return the new head (unchanged through recursion) */
    return new_head;
}

/* =============================================================================
 * print_list - Display all elements in the list
 * =============================================================================
 * 
 * Traverses the list and prints each element in a visual format.
 * 
 * Parameters:
 *   head - Pointer to the head of the list
 * 
 * Output format: [data1] -> [data2] -> ... -> NULL
 */
void print_list(Node *head) {
    if (head == NULL) {
        printf("List is empty (NULL)\n");
        return;
    }
    
    Node *current = head;
    printf("List: ");
    
    while (current != NULL) {
        printf("[%d]", current->data);
        if (current->next != NULL) {
            printf(" -> ");
        }
        current = current->next;
    }
    
    printf(" -> NULL\n");
}

/* =============================================================================
 * print_list_detailed - Display list with memory addresses (for debugging)
 * =============================================================================
 * 
 * Prints detailed information about each node including memory addresses.
 * Useful for debugging and understanding the memory layout.
 * 
 * Parameters:
 *   head - Pointer to the head of the list
 */
void print_list_detailed(Node *head) {
    if (head == NULL) {
        printf("List is empty (NULL)\n");
        return;
    }
    
    printf("\n=== Detailed List View ===\n");
    printf("%-8s  %-16s  %-8s  %-16s\n", "Index", "Address", "Data", "Next");
    printf("------------------------------------------------------\n");
    
    Node *current = head;
    int index = 0;
    
    while (current != NULL) {
        printf("%-8d  %-16p  %-8d  %-16p\n",
               index,
               (void *)current,
               current->data,
               (void *)current->next);
        current = current->next;
        index++;
    }
    
    printf("------------------------------------------------------\n");
    printf("Total nodes: %d\n\n", index);
}

/* =============================================================================
 * free_list - Deallocate all memory used by the list
 * =============================================================================
 * 
 * CRITICAL: This function must be called when done with the list to prevent
 * memory leaks. It traverses the list and frees each node.
 * 
 * Important: We must save the next pointer BEFORE freeing the current node,
 * because after free() the memory is invalid and we can't access next.
 * 
 * Parameters:
 *   head - Pointer to the head of the list
 * 
 * Note: After calling this function, the caller should set their head
 *       pointer to NULL to avoid using freed memory (dangling pointer).
 */
void free_list(Node *head) {
    Node *current = head;
    Node *next;
    int freed_count = 0;
    
    while (current != NULL) {
        next = current->next;  /* Save next pointer BEFORE freeing */
        free(current);          /* Free the current node */
        current = next;         /* Move to the next node */
        freed_count++;
    }
    
    printf("Memory cleanup: Freed %d node(s)\n", freed_count);
}

/* =============================================================================
 * Main Function - Demonstration of all linked list operations
 * =============================================================================
 */
int main(void) {
    Node *list = NULL;  /* Initialize empty list */
    
    printf("============================================================\n");
    printf("    Singly Linked List Implementation Demo\n");
    printf("============================================================\n\n");
    
    /* =========================================================================
     * Test 1: Basic insertions
     * =========================================================================
     */
    printf("--- Test 1: Basic Insertions ---\n\n");
    
    /* Insert at head */
    printf("Inserting 30, 20, 10 at head:\n");
    list = insert_head(list, 30);
    list = insert_head(list, 20);
    list = insert_head(list, 10);
    print_list(list);
    
    /* Insert at tail */
    printf("\nInserting 40, 50 at tail:\n");
    list = insert_tail(list, 40);
    list = insert_tail(list, 50);
    print_list(list);
    
    /* Insert at specific position */
    printf("\nInserting 25 at position 2:\n");
    list = insert_at_position(list, 25, 2);
    print_list(list);
    
    printf("\nInserting 5 at position 0 (should become new head):\n");
    list = insert_at_position(list, 5, 0);
    print_list(list);
    
    /* Show detailed view */
    print_list_detailed(list);
    
    /* =========================================================================
     * Test 2: Search operations
     * =========================================================================
     */
    printf("--- Test 2: Search Operations ---\n\n");
    
    printf("List length: %d\n", get_length(list));
    
    /* Find existing values */
    int search_values[] = {25, 50, 100};
    for (int i = 0; i < 3; i++) {
        Node *found = find_node(list, search_values[i]);
        if (found != NULL) {
            printf("Found node with value %d at address %p\n",
                   search_values[i], (void *)found);
        } else {
            printf("Value %d not found in list\n", search_values[i]);
        }
    }
    
    /* =========================================================================
     * Test 3: Deletion operations
     * =========================================================================
     */
    printf("\n--- Test 3: Deletion Operations ---\n\n");
    
    printf("Current list:\n");
    print_list(list);
    
    /* Delete by value */
    printf("\nDeleting node with value 25:\n");
    list = delete_node(list, 25);
    print_list(list);
    
    /* Delete head */
    printf("\nDeleting head node (value 5):\n");
    list = delete_node(list, 5);
    print_list(list);
    
    /* Delete tail */
    printf("\nDeleting tail node (value 50):\n");
    list = delete_node(list, 50);
    print_list(list);
    
    /* Try to delete non-existent value */
    printf("\nTrying to delete non-existent value 999:\n");
    list = delete_node(list, 999);
    print_list(list);
    
    /* Delete by position */
    printf("\nDeleting node at position 1:\n");
    list = delete_at_position(list, 1);
    print_list(list);
    
    /* =========================================================================
     * Test 4: List reversal
     * =========================================================================
     */
    printf("\n--- Test 4: List Reversal ---\n\n");
    
    /* Rebuild list for reversal demo */
    free_list(list);
    list = NULL;
    
    printf("\nBuilding new list for reversal demo:\n");
    for (int i = 1; i <= 5; i++) {
        list = insert_tail(list, i * 10);
    }
    print_list(list);
    
    /* Iterative reversal */
    printf("\nReversing list (iterative method):\n");
    list = reverse_list(list);
    print_list(list);
    
    /* Reverse again using recursive method */
    printf("\nReversing list again (recursive method):\n");
    list = reverse_list_recursive(list);
    print_list(list);
    
    /* =========================================================================
     * Test 5: Edge cases
     * =========================================================================
     */
    printf("\n--- Test 5: Edge Cases ---\n\n");
    
    /* Free and test empty list operations */
    free_list(list);
    list = NULL;
    
    printf("\nTesting operations on empty list:\n");
    print_list(list);
    printf("Length of empty list: %d\n", get_length(list));
    
    Node *not_found = find_node(list, 10);
    printf("Find 10 in empty list: %s\n", not_found ? "Found" : "Not found");
    
    list = delete_node(list, 10);
    
    printf("\nReversing empty list:\n");
    list = reverse_list(list);
    print_list(list);
    
    /* Single node operations */
    printf("\nTesting with single node:\n");
    list = insert_head(list, 42);
    print_list(list);
    
    printf("\nReversing single-node list:\n");
    list = reverse_list(list);
    print_list(list);
    
    printf("\nDeleting the only node:\n");
    list = delete_node(list, 42);
    print_list(list);
    
    /* =========================================================================
     * Test 6: Large list performance demonstration
     * =========================================================================
     */
    printf("\n--- Test 6: Building Larger List ---\n\n");
    
    printf("Inserting 10 elements at alternating positions:\n");
    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            list = insert_head(list, i);
        } else {
            list = insert_tail(list, i);
        }
    }
    print_list(list);
    print_list_detailed(list);
    
    /* =========================================================================
     * Cleanup
     * =========================================================================
     */
    printf("\n--- Cleanup ---\n\n");
    free_list(list);
    list = NULL;  /* Good practice: set to NULL after freeing */
    
    printf("\nAll tests completed successfully!\n");
    printf("============================================================\n");
    
    return 0;
}
