from typing import Set


def merge_lists(primary_list: list, secondary_list: list) -> list:
    """Merge two lists together and return a unique list"""
    return primary_list + [item for item in secondary_list if item not in primary_list]


def value_in_set(value: str, valid_options: Set[str], option_name: str = 'option',
                 custom_error_message: str = ''):
    """
    Check if a value is contained in a list of valid options. This is supplied as a convenience function
    and is intended to be used with the input field validation on creates/updates.

    :param str value: Value to check
    :param set of str valid_options: List of options that the value should be included in for this to be successful
    :param str option_name: Optional descriptive name of the option that can be used to enrich an error message.
    :param str custom_error_message: Optional custom error message to return instead of the default one.
    :return: Dictionary that can be used with the field_validation
    :rtype: dict
    """
    return {
        'result': value in valid_options,
        'message': custom_error_message or f'{value} is not a valid {option_name}. Valid options: {valid_options}'
    }
