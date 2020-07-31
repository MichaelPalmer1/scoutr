def merge_lists(primary_list, secondary_list):
    """Merge two lists together and return a unique list"""
    return primary_list + [item for item in secondary_list if item not in primary_list]
