#include <stddef.h>
#include "picotls.h"

#define LAYOUT_ASSERT_EQ(a, b) _Static_assert((a) == (b), "picotls layout mismatch")

LAYOUT_ASSERT_EQ(offsetof(ptls_iovec_t, base), 0);
LAYOUT_ASSERT_EQ(offsetof(ptls_iovec_t, len), sizeof(void *));
