"""Closed comparison / half-open access bounds over representable addresses."""
LIMIT = 2**64
EMPTY = (1, 0)


def normalize(bounds):
    if bounds is None:
        return None
    lower, upper = bounds
    if lower > upper or upper < 0 or lower >= LIMIT:
        return EMPTY
    return max(0, lower), min(LIMIT, upper)


def intersect(left, right):
    if left is None:
        return normalize(right)
    if right is None:
        return normalize(left)
    left, right = normalize(left), normalize(right)
    return normalize((max(left[0], right[0]), min(left[1], right[1])))


def record(bounds):
    bounds = normalize(bounds)
    if bounds is None:
        return None
    if bounds == EMPTY:
        return {'some': {'lower': 0, 'upper': 0, 'upper_is_limit': False, 'empty': True}}
    lower, upper = bounds
    return {'some': {'lower': lower, 'upper': 0 if upper == LIMIT else upper,
                     'upper_is_limit': upper == LIMIT, 'empty': False}}
