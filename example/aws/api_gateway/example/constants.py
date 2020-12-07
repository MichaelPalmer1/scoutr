import re

from scoutr.providers.aws import DynamoAPI


"""
Valid option groups
"""
VALID_STATUSES = [
    'Active',
    'Inactive'
]

"""
Fields required for record creation
"""
CREATE_FIELDS = {
    'id': lambda value, item, existing_item: {
        'result': re.match(r'^\d{6}', value),
        'message': 'Invalid id'
    },
    'description': lambda value, item, existing_item: isinstance(value, str),
    'status': lambda value, item, existing_item: DynamoAPI.value_in_set(
        value=value,
        valid_options=VALID_STATUSES,
        option_name='status'
    )
}

"""
Field validation for record updates
"""
UPDATE_FIELDS = {
    'description': lambda value, item, existing_item: isinstance(value, str),
    'type': lambda value, item, existing_item: {
        'result': existing_item.get('type') == item.get('type') if 'type' in item else False,
        'message': 'Type cannot be modified'
    }
}

"""
Fields that cannot be updated
"""
RESTRICTED_FIELDS = [
    'id',
    'type'
]
UPDATE_FIELDS.update({
    field: lambda value, item, existing_item, field_name=field: {
        'result': False,
        'message': f'{field_name} cannot be updated'
    }
    for field in RESTRICTED_FIELDS
})
