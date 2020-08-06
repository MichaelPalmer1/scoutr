For convenience, support for data validation on all create and update calls is supported. In order to implement the
validation, a dictionary should be passed to the `field_validation` argument of the `create()` or `update()` methods
of `DynamoAPI`. The syntax of this dictionary is outlined below.

On `create()` calls, all items specified in the `field_validation` dictionary are assumed to be required fields. If a
field is missing from the user input, an error will be thrown saying that the field is required.

## Syntax

```python
FIELD_VALIDATION = {
    'field_name_1': lambda value, item, existing_item: callable_that_returns_a_bool,
    'field_name_2': lambda value, item, existing_item: callable_that_returns_a_dict,
    'field_name_3': callable_that_returns_a_bool,
    'field_name_4': callable_that_returns_a_dict
}
```

The key of each item in the dictionary should match a field name that you want to perform validation against. The
corresponding value for the key should be a callable that either returns a bool or a dict formatted as:
```python
{
    'result': boolean that indicates whether this field was valid or not,
    'message': 'custom error message to return to the user'
}
```

The callable that you provide can either be a function or a lambda. The method signature of both options **must accept**
three arguments:
- `value` - Contains the input value for this field
- `item` - Contains the entire data object that was passed from the user
- `existing_item` - Contains the existing data object in Dynamo. This will only have a value on update calls. For
    create calls, this will be `None`.

## Example
```python
def validate_user(value, item, existing_item=None):
    if isinstance(existing_item, dict):
        item_type = existing_item.get('type')
    else:
        item_type = item.get('type')

    if not item_type:
        return {
            'result': False,
            'message': 'Type field is required'
        }

    if item_type == '1':
        return {
            'result': re.match('^\d{9}$', value),
            'message': 'Invalid user for type %s' % item_type
        }
    elif item_type == '2':
        return {
            'result': re.match('^.+@example.com$', value),
            'message': 'Invalid user for type %s' % item_type
        }
    else:
        return False

FIELD_VALIDATION = {
    'user': validate_user,
    'type': lambda value, item, existing_item: DynamoAPI.value_in_list(
        value=value,
        valid_options=['1', '2'],
        option_name='type'
    ),
    'description': lambda value, item, existing_item: isinstance(value, str),
    'name': lambda value, item, existing_item: {
        'result': re.match('^\w+ \w+$', value),
        'message': 'Invalid name format'
    }
}
```
