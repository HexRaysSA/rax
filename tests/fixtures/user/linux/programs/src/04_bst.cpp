/**
 * Binary Search Tree Implementation in C++17
 * 
 * A fully templated BST with smart pointer memory management,
 * comprehensive tree operations, and proper copy/move semantics.
 */

#include <iostream>
#include <memory>
#include <functional>
#include <string>
#include <queue>
#include <sstream>
#include <cassert>
#include <vector>
#include <algorithm>
#include <cmath>

template <typename T>
class BST {
public:
    // Node structure using unique_ptr for automatic memory management
    struct Node {
        T data;
        std::unique_ptr<Node> left;
        std::unique_ptr<Node> right;
        
        explicit Node(const T& value) : data(value), left(nullptr), right(nullptr) {}
        explicit Node(T&& value) : data(std::move(value)), left(nullptr), right(nullptr) {}
        
        // Deep copy constructor for node subtree
        Node(const Node& other) : data(other.data), left(nullptr), right(nullptr) {
            if (other.left) {
                left = std::make_unique<Node>(*other.left);
            }
            if (other.right) {
                right = std::make_unique<Node>(*other.right);
            }
        }
    };

private:
    std::unique_ptr<Node> root_;
    size_t size_;

    // Helper function to deep copy a subtree
    std::unique_ptr<Node> cloneSubtree(const Node* node) const {
        if (!node) return nullptr;
        return std::make_unique<Node>(*node);
    }

    // Recursive insert helper
    std::unique_ptr<Node>& insertHelper(std::unique_ptr<Node>& node, const T& value) {
        if (!node) {
            node = std::make_unique<Node>(value);
            ++size_;
            return node;
        }
        if (value < node->data) {
            return insertHelper(node->left, value);
        } else if (value > node->data) {
            return insertHelper(node->right, value);
        }
        // Value already exists, return existing node
        return node;
    }

    // Move version of insert helper
    std::unique_ptr<Node>& insertHelper(std::unique_ptr<Node>& node, T&& value) {
        if (!node) {
            node = std::make_unique<Node>(std::move(value));
            ++size_;
            return node;
        }
        if (value < node->data) {
            return insertHelper(node->left, std::move(value));
        } else if (value > node->data) {
            return insertHelper(node->right, std::move(value));
        }
        return node;
    }

    // Find minimum node in subtree
    Node* findMinNode(Node* node) const {
        if (!node) return nullptr;
        while (node->left) {
            node = node->left.get();
        }
        return node;
    }

    // Find maximum node in subtree
    Node* findMaxNode(Node* node) const {
        if (!node) return nullptr;
        while (node->right) {
            node = node->right.get();
        }
        return node;
    }

    // Recursive remove helper - returns the modified subtree
    std::unique_ptr<Node> removeHelper(std::unique_ptr<Node> node, const T& value, bool& removed) {
        if (!node) {
            removed = false;
            return nullptr;
        }

        if (value < node->data) {
            node->left = removeHelper(std::move(node->left), value, removed);
        } else if (value > node->data) {
            node->right = removeHelper(std::move(node->right), value, removed);
        } else {
            // Found the node to remove
            removed = true;
            --size_;

            // Case 1: No children (leaf node)
            if (!node->left && !node->right) {
                return nullptr;
            }
            
            // Case 2: One child
            if (!node->left) {
                return std::move(node->right);
            }
            if (!node->right) {
                return std::move(node->left);
            }
            
            // Case 3: Two children - replace with inorder successor
            Node* successor = findMinNode(node->right.get());
            node->data = successor->data;
            ++size_; // Compensate for the decrement in recursive call
            node->right = removeHelper(std::move(node->right), successor->data, removed);
        }
        return node;
    }

    // Recursive find helper
    const Node* findHelper(const Node* node, const T& value) const {
        if (!node) return nullptr;
        if (value < node->data) {
            return findHelper(node->left.get(), value);
        } else if (value > node->data) {
            return findHelper(node->right.get(), value);
        }
        return node;
    }

    // Calculate height of subtree
    int heightHelper(const Node* node) const {
        if (!node) return -1; // Empty tree has height -1, single node has height 0
        return 1 + std::max(heightHelper(node->left.get()), heightHelper(node->right.get()));
    }

    // Check if subtree is balanced (height difference <= 1 for all nodes)
    bool isBalancedHelper(const Node* node, int& height) const {
        if (!node) {
            height = -1;
            return true;
        }

        int leftHeight, rightHeight;
        bool leftBalanced = isBalancedHelper(node->left.get(), leftHeight);
        bool rightBalanced = isBalancedHelper(node->right.get(), rightHeight);

        height = 1 + std::max(leftHeight, rightHeight);

        return leftBalanced && rightBalanced && 
               std::abs(leftHeight - rightHeight) <= 1;
    }

    // Inorder traversal helper
    void inorderHelper(const Node* node, const std::function<void(const T&)>& callback) const {
        if (!node) return;
        inorderHelper(node->left.get(), callback);
        callback(node->data);
        inorderHelper(node->right.get(), callback);
    }

    // Preorder traversal helper
    void preorderHelper(const Node* node, const std::function<void(const T&)>& callback) const {
        if (!node) return;
        callback(node->data);
        preorderHelper(node->left.get(), callback);
        preorderHelper(node->right.get(), callback);
    }

    // Postorder traversal helper
    void postorderHelper(const Node* node, const std::function<void(const T&)>& callback) const {
        if (!node) return;
        postorderHelper(node->left.get(), callback);
        postorderHelper(node->right.get(), callback);
        callback(node->data);
    }

public:
    // Default constructor
    BST() : root_(nullptr), size_(0) {}

    // Copy constructor - deep copy
    BST(const BST& other) : root_(nullptr), size_(other.size_) {
        if (other.root_) {
            root_ = cloneSubtree(other.root_.get());
        }
    }

    // Move constructor
    BST(BST&& other) noexcept : root_(std::move(other.root_)), size_(other.size_) {
        other.size_ = 0;
    }

    // Copy assignment operator
    BST& operator=(const BST& other) {
        if (this != &other) {
            BST temp(other);
            std::swap(root_, temp.root_);
            std::swap(size_, temp.size_);
        }
        return *this;
    }

    // Move assignment operator
    BST& operator=(BST&& other) noexcept {
        if (this != &other) {
            root_ = std::move(other.root_);
            size_ = other.size_;
            other.size_ = 0;
        }
        return *this;
    }

    // Destructor is automatically handled by unique_ptr

    // Insert a value (copy)
    void insert(const T& value) {
        insertHelper(root_, value);
    }

    // Insert a value (move)
    void insert(T&& value) {
        insertHelper(root_, std::move(value));
    }

    // Insert multiple values using initializer list
    void insert(std::initializer_list<T> values) {
        for (const auto& value : values) {
            insert(value);
        }
    }

    // Remove a value, returns true if value was found and removed
    bool remove(const T& value) {
        bool removed = true;
        root_ = removeHelper(std::move(root_), value, removed);
        return removed;
    }

    // Find a value, returns pointer to data or nullptr if not found
    const T* find(const T& value) const {
        const Node* node = findHelper(root_.get(), value);
        return node ? &node->data : nullptr;
    }

    // Check if value exists in tree
    bool contains(const T& value) const {
        return find(value) != nullptr;
    }

    // Find minimum value
    const T* findMin() const {
        Node* minNode = findMinNode(root_.get());
        return minNode ? &minNode->data : nullptr;
    }

    // Find maximum value
    const T* findMax() const {
        Node* maxNode = findMaxNode(root_.get());
        return maxNode ? &maxNode->data : nullptr;
    }

    // Get tree height (-1 for empty tree, 0 for single node)
    int height() const {
        return heightHelper(root_.get());
    }

    // Get number of nodes
    size_t size() const {
        return size_;
    }

    // Check if tree is empty
    bool empty() const {
        return size_ == 0;
    }

    // Check if tree is balanced (AVL property)
    bool isBalanced() const {
        int height;
        return isBalancedHelper(root_.get(), height);
    }

    // Clear the tree
    void clear() {
        root_.reset();
        size_ = 0;
    }

    // Inorder traversal with callback
    void inorder(const std::function<void(const T&)>& callback) const {
        inorderHelper(root_.get(), callback);
    }

    // Preorder traversal with callback
    void preorder(const std::function<void(const T&)>& callback) const {
        preorderHelper(root_.get(), callback);
    }

    // Postorder traversal with callback
    void postorder(const std::function<void(const T&)>& callback) const {
        postorderHelper(root_.get(), callback);
    }

    // Level-order (BFS) traversal with callback
    void levelorder(const std::function<void(const T&)>& callback) const {
        if (!root_) return;
        
        std::queue<const Node*> q;
        q.push(root_.get());
        
        while (!q.empty()) {
            const Node* current = q.front();
            q.pop();
            callback(current->data);
            
            if (current->left) q.push(current->left.get());
            if (current->right) q.push(current->right.get());
        }
    }

    // Print tree traversals to ostream
    void printInorder(std::ostream& os = std::cout) const {
        os << "Inorder: ";
        bool first = true;
        inorder([&os, &first](const T& value) {
            if (!first) os << " -> ";
            os << value;
            first = false;
        });
        os << "\n";
    }

    void printPreorder(std::ostream& os = std::cout) const {
        os << "Preorder: ";
        bool first = true;
        preorder([&os, &first](const T& value) {
            if (!first) os << " -> ";
            os << value;
            first = false;
        });
        os << "\n";
    }

    void printPostorder(std::ostream& os = std::cout) const {
        os << "Postorder: ";
        bool first = true;
        postorder([&os, &first](const T& value) {
            if (!first) os << " -> ";
            os << value;
            first = false;
        });
        os << "\n";
    }

    void printLevelorder(std::ostream& os = std::cout) const {
        os << "Level-order: ";
        bool first = true;
        levelorder([&os, &first](const T& value) {
            if (!first) os << " -> ";
            os << value;
            first = false;
        });
        os << "\n";
    }

    // Collect values into a vector (useful for testing)
    std::vector<T> toVector() const {
        std::vector<T> result;
        result.reserve(size_);
        inorder([&result](const T& value) {
            result.push_back(value);
        });
        return result;
    }

    // Pretty print tree structure
    void printTree(std::ostream& os = std::cout) const {
        if (!root_) {
            os << "(empty tree)\n";
            return;
        }
        printTreeHelper(os, root_.get(), "", true);
    }

private:
    void printTreeHelper(std::ostream& os, const Node* node, 
                         const std::string& prefix, bool isLast) const {
        if (!node) return;
        
        os << prefix;
        os << (isLast ? "`-- " : "|-- ");
        os << node->data << "\n";
        
        std::string newPrefix = prefix + (isLast ? "    " : "|   ");
        
        // Print right first so it appears above left in the visual
        if (node->right || node->left) {
            printTreeHelper(os, node->right.get(), newPrefix, !node->left);
            printTreeHelper(os, node->left.get(), newPrefix, true);
        }
    }
};

// ============================================================================
// Test Functions
// ============================================================================

void printSeparator(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(60, '=') << "\n\n";
}

void testIntBST() {
    printSeparator("Testing BST<int>");

    // Test 1: Basic insertion and traversals
    std::cout << "--- Test 1: Basic insertion and traversals ---\n";
    BST<int> tree;
    tree.insert({50, 30, 70, 20, 40, 60, 80});
    
    std::cout << "Inserted: 50, 30, 70, 20, 40, 60, 80\n\n";
    std::cout << "Tree structure:\n";
    tree.printTree();
    std::cout << "\n";
    
    tree.printInorder();
    tree.printPreorder();
    tree.printPostorder();
    tree.printLevelorder();
    
    // Test 2: Tree properties
    std::cout << "\n--- Test 2: Tree properties ---\n";
    std::cout << "Size: " << tree.size() << " (expected: 7)\n";
    std::cout << "Height: " << tree.height() << " (expected: 2)\n";
    std::cout << "Is balanced: " << (tree.isBalanced() ? "yes" : "no") << " (expected: yes)\n";
    std::cout << "Is empty: " << (tree.empty() ? "yes" : "no") << " (expected: no)\n";

    // Test 3: Find operations
    std::cout << "\n--- Test 3: Find operations ---\n";
    auto minVal = tree.findMin();
    auto maxVal = tree.findMax();
    std::cout << "Min value: " << (minVal ? std::to_string(*minVal) : "null") << " (expected: 20)\n";
    std::cout << "Max value: " << (maxVal ? std::to_string(*maxVal) : "null") << " (expected: 80)\n";
    
    std::cout << "Contains 40: " << (tree.contains(40) ? "yes" : "no") << " (expected: yes)\n";
    std::cout << "Contains 45: " << (tree.contains(45) ? "yes" : "no") << " (expected: no)\n";
    
    auto found = tree.find(60);
    std::cout << "Find 60: " << (found ? std::to_string(*found) : "not found") << " (expected: 60)\n";

    // Test 4: Removal operations
    std::cout << "\n--- Test 4: Removal operations ---\n";
    
    // Remove leaf node
    std::cout << "Removing 20 (leaf): " << (tree.remove(20) ? "success" : "failed") << "\n";
    std::cout << "Tree after removing 20:\n";
    tree.printTree();
    tree.printInorder();
    
    // Remove node with one child
    tree.insert(25);  // Add back a node to create interesting structure
    std::cout << "\nAfter inserting 25:\n";
    tree.printTree();
    
    std::cout << "Removing 30 (one child): " << (tree.remove(30) ? "success" : "failed") << "\n";
    std::cout << "Tree after removing 30:\n";
    tree.printTree();
    tree.printInorder();
    
    // Remove node with two children
    std::cout << "\nRemoving 50 (root, two children): " << (tree.remove(50) ? "success" : "failed") << "\n";
    std::cout << "Tree after removing 50 (root):\n";
    tree.printTree();
    tree.printInorder();
    
    // Remove non-existent value
    std::cout << "\nRemoving 999 (non-existent): " << (tree.remove(999) ? "success" : "failed") << " (expected: failed)\n";
    
    std::cout << "\nFinal size: " << tree.size() << " (expected: 5)\n";

    // Test 5: Copy constructor
    std::cout << "\n--- Test 5: Copy constructor ---\n";
    BST<int> treeCopy(tree);
    std::cout << "Original tree:\n";
    tree.printInorder();
    std::cout << "Copied tree:\n";
    treeCopy.printInorder();
    
    // Modify original, verify copy is independent
    tree.insert(100);
    std::cout << "\nAfter inserting 100 into original:\n";
    std::cout << "Original: ";
    tree.printInorder();
    std::cout << "Copy (should be unchanged): ";
    treeCopy.printInorder();

    // Test 6: Move semantics
    std::cout << "\n--- Test 6: Move semantics ---\n";
    BST<int> treeToMove;
    treeToMove.insert({1, 2, 3, 4, 5});
    std::cout << "Tree to move: ";
    treeToMove.printInorder();
    std::cout << "Size before move: " << treeToMove.size() << "\n";
    
    BST<int> movedTree(std::move(treeToMove));
    std::cout << "Moved tree: ";
    movedTree.printInorder();
    std::cout << "Original after move (should be empty): size = " << treeToMove.size() << "\n";

    // Test 7: Assignment operators
    std::cout << "\n--- Test 7: Assignment operators ---\n";
    BST<int> assigned;
    assigned = treeCopy;  // Copy assignment
    std::cout << "After copy assignment: ";
    assigned.printInorder();
    
    BST<int> moveAssigned;
    moveAssigned = std::move(movedTree);  // Move assignment
    std::cout << "After move assignment: ";
    moveAssigned.printInorder();

    // Test 8: Edge cases
    std::cout << "\n--- Test 8: Edge cases ---\n";
    BST<int> emptyTree;
    std::cout << "Empty tree - size: " << emptyTree.size() << ", height: " << emptyTree.height() << "\n";
    std::cout << "Empty tree - isBalanced: " << (emptyTree.isBalanced() ? "yes" : "no") << "\n";
    std::cout << "Empty tree - findMin: " << (emptyTree.findMin() ? "found" : "null") << "\n";
    
    BST<int> singleNode;
    singleNode.insert(42);
    std::cout << "Single node - size: " << singleNode.size() << ", height: " << singleNode.height() << "\n";
    std::cout << "Single node - isBalanced: " << (singleNode.isBalanced() ? "yes" : "no") << "\n";

    // Test 9: Unbalanced tree
    std::cout << "\n--- Test 9: Unbalanced tree detection ---\n";
    BST<int> unbalanced;
    unbalanced.insert({1, 2, 3, 4, 5});  // Creates a right-skewed tree
    std::cout << "Right-skewed tree (1,2,3,4,5):\n";
    unbalanced.printTree();
    std::cout << "Height: " << unbalanced.height() << " (expected: 4)\n";
    std::cout << "Is balanced: " << (unbalanced.isBalanced() ? "yes" : "no") << " (expected: no)\n";

    // Test 10: Duplicate insertion
    std::cout << "\n--- Test 10: Duplicate handling ---\n";
    BST<int> dupTree;
    dupTree.insert({5, 3, 7, 3, 5, 7});  // Duplicates should be ignored
    std::cout << "Inserted: 5, 3, 7, 3, 5, 7 (duplicates should be ignored)\n";
    std::cout << "Size: " << dupTree.size() << " (expected: 3)\n";
    dupTree.printInorder();
}

void testStringBST() {
    printSeparator("Testing BST<std::string>");

    // Test 1: Basic string operations
    std::cout << "--- Test 1: Basic string insertion ---\n";
    BST<std::string> tree;
    tree.insert("mango");
    tree.insert("apple");
    tree.insert("zebra");
    tree.insert("banana");
    tree.insert("orange");
    tree.insert("kiwi");
    tree.insert("grape");
    
    std::cout << "Inserted: mango, apple, zebra, banana, orange, kiwi, grape\n\n";
    std::cout << "Tree structure:\n";
    tree.printTree();
    std::cout << "\n";
    
    tree.printInorder();
    tree.printPreorder();

    // Test 2: String-specific operations
    std::cout << "\n--- Test 2: String find operations ---\n";
    auto minStr = tree.findMin();
    auto maxStr = tree.findMax();
    std::cout << "Min: " << (minStr ? *minStr : "null") << " (expected: apple)\n";
    std::cout << "Max: " << (maxStr ? *maxStr : "null") << " (expected: zebra)\n";
    
    std::cout << "Contains 'banana': " << (tree.contains("banana") ? "yes" : "no") << "\n";
    std::cout << "Contains 'cherry': " << (tree.contains("cherry") ? "yes" : "no") << "\n";

    // Test 3: Move semantics with strings
    std::cout << "\n--- Test 3: Move semantics with strings ---\n";
    std::string moveMe = "watermelon";
    std::cout << "Inserting via move: '" << moveMe << "'\n";
    tree.insert(std::move(moveMe));
    std::cout << "After move, original string: '" << moveMe << "' (may be empty or unchanged)\n";
    tree.printInorder();

    // Test 4: Removal
    std::cout << "\n--- Test 4: String removal ---\n";
    tree.remove("mango");  // Remove root
    std::cout << "After removing 'mango':\n";
    tree.printTree();
    tree.printInorder();

    // Test 5: Collecting to vector
    std::cout << "\n--- Test 5: Collect to vector ---\n";
    auto vec = tree.toVector();
    std::cout << "Sorted vector: ";
    for (const auto& s : vec) {
        std::cout << s << " ";
    }
    std::cout << "\n";

    // Test 6: Copy and verify independence
    std::cout << "\n--- Test 6: Deep copy verification ---\n";
    BST<std::string> copy = tree;
    tree.insert("pineapple");
    copy.insert("strawberry");
    
    std::cout << "Original (added pineapple): ";
    tree.printInorder();
    std::cout << "Copy (added strawberry): ";
    copy.printInorder();
}

void testCallbackTraversals() {
    printSeparator("Testing Callback Traversals");

    BST<int> tree;
    tree.insert({4, 2, 6, 1, 3, 5, 7});

    std::cout << "Tree structure:\n";
    tree.printTree();
    std::cout << "\n";

    // Test with accumulator callback
    std::cout << "--- Sum using inorder callback ---\n";
    int sum = 0;
    tree.inorder([&sum](const int& val) {
        sum += val;
    });
    std::cout << "Sum of all elements: " << sum << " (expected: 28)\n";

    // Test with filter callback
    std::cout << "\n--- Filter even numbers using preorder ---\n";
    std::vector<int> evenNumbers;
    tree.preorder([&evenNumbers](const int& val) {
        if (val % 2 == 0) {
            evenNumbers.push_back(val);
        }
    });
    std::cout << "Even numbers (preorder): ";
    for (int n : evenNumbers) {
        std::cout << n << " ";
    }
    std::cout << "\n";

    // Test with transformation callback
    std::cout << "\n--- Transform using level-order ---\n";
    std::vector<std::string> transformed;
    tree.levelorder([&transformed](const int& val) {
        transformed.push_back("node_" + std::to_string(val));
    });
    std::cout << "Transformed (level-order): ";
    for (const auto& s : transformed) {
        std::cout << s << " ";
    }
    std::cout << "\n";
}

void runAssertions() {
    printSeparator("Running Assertions");

    // Create a known tree structure
    BST<int> tree;
    tree.insert({50, 25, 75, 10, 30, 60, 90});

    // Basic property assertions
    assert(tree.size() == 7);
    assert(tree.height() == 2);
    assert(tree.isBalanced() == true);
    assert(tree.empty() == false);
    std::cout << "Basic property assertions: PASSED\n";

    // Find assertions
    assert(tree.contains(50) == true);
    assert(tree.contains(25) == true);
    assert(tree.contains(100) == false);
    assert(*tree.findMin() == 10);
    assert(*tree.findMax() == 90);
    assert(*tree.find(60) == 60);
    assert(tree.find(100) == nullptr);
    std::cout << "Find operation assertions: PASSED\n";

    // Inorder should be sorted
    auto sorted = tree.toVector();
    assert(std::is_sorted(sorted.begin(), sorted.end()));
    std::cout << "Sorted order assertion: PASSED\n";

    // Remove assertions
    assert(tree.remove(25) == true);
    assert(tree.size() == 6);
    assert(tree.contains(25) == false);
    assert(tree.remove(25) == false);  // Already removed
    std::cout << "Remove operation assertions: PASSED\n";

    // Copy assertion
    BST<int> copy(tree);
    assert(copy.size() == tree.size());
    tree.insert(1000);
    assert(copy.size() != tree.size());  // Copy is independent
    std::cout << "Copy independence assertion: PASSED\n";

    // Move assertion
    size_t originalSize = tree.size();
    BST<int> moved(std::move(tree));
    assert(moved.size() == originalSize);
    assert(tree.size() == 0);  // Original should be empty
    std::cout << "Move semantics assertion: PASSED\n";

    // Clear assertion
    moved.clear();
    assert(moved.empty() == true);
    assert(moved.size() == 0);
    assert(moved.height() == -1);
    std::cout << "Clear operation assertion: PASSED\n";

    // Empty tree assertions
    BST<int> empty;
    assert(empty.size() == 0);
    assert(empty.height() == -1);
    assert(empty.isBalanced() == true);  // Empty tree is balanced
    assert(empty.findMin() == nullptr);
    assert(empty.findMax() == nullptr);
    std::cout << "Empty tree assertions: PASSED\n";

    std::cout << "\nAll assertions PASSED!\n";
}

int main() {
    std::cout << "Binary Search Tree Implementation Test Suite\n";
    std::cout << "============================================\n";
    std::cout << "Using C++17 with smart pointers (unique_ptr)\n";
    
    // Run all tests
    testIntBST();
    testStringBST();
    testCallbackTraversals();
    runAssertions();

    printSeparator("All Tests Completed Successfully!");
    
    return 0;
}
