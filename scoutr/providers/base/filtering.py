import re
from abc import abstractmethod
from decimal import Decimal
from typing import Any
from urllib.parse import unquote_plus

from scoutr.exceptions import BadRequestException
from scoutr.models.user import User


class Filtering:

    OPERATION_EQUAL = 'eq'
    OPERATION_NOT_EQUAL = 'ne'
    OPERATION_STARTS_WITH = 'startswith'
    OPERATION_CONTAINS = 'contains'
    OPERATION_NOT_CONTAINS = 'notcontains'
    OPERATION_EXISTS = 'exists'
    OPERATION_GREATER_THAN = 'gt'
    OPERATION_LESS_THAN = 'lt'
    OPERATION_GREATER_THAN_EQUAL = 'ge'
    OPERATION_LESS_THAN_EQUAL = 'le'
    OPERATION_BETWEEN = 'between'
    OPERATION_IN = 'in'
    OPERATION_NOT_IN = 'notin'

    NUMERIC_OPERATIONS = (
        OPERATION_GREATER_THAN,
        OPERATION_LESS_THAN,
        OPERATION_GREATER_THAN_EQUAL,
        OPERATION_LESS_THAN_EQUAL,
    )

    def operations(self) -> dict:
        """
        List of supported operations

        :return: Supported operations
        :rtype: dict
        """
        return {}

    @abstractmethod
    def And(self, condition1, condition2):
        raise NotImplementedError

    @abstractmethod
    def Or(self, condition1, condition2):
        raise NotImplementedError

    @abstractmethod
    def equals(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def not_equal(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def starts_with(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def contains(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def not_contains(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def exists(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def greater_than(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def less_than(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def greater_than_equal(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def less_than_equal(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def between(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def is_in(self, attr: str, value):
        raise NotImplementedError

    @abstractmethod
    def not_in(self, attr: str, value):
        raise NotImplementedError

    def user_filters(self, user: User) -> Any:
        conditions = None
        for item in user.filter_fields:
            user_conditions = None
            if isinstance(item.value, list):
                try:
                    condition = self.is_in(item.field, item.value)
                except NotImplementedError:
                    raise BadRequestException(
                        'Failed to generate user condition - IN operation is not supported by this provider.'
                    )
                user_conditions = self.And(user_conditions, condition)
            elif isinstance(item.value, str):
                condition = self.equals(item.field, item.value)
                user_conditions = self.And(user_conditions, condition)
            else:
                print('Received value of unknown type', item.value)
                print('Type', type(item.value))
                continue

            conditions = self.Or(conditions, user_conditions)

        return conditions

    def filter(self, user: User, filters: dict):
        conditions = self.user_filters(user)

        # Build filters that were passed in
        for key, value in filters.items():
            if isinstance(value, list):
                # Multi-value filter
                for item in value:
                    if not isinstance(item, str):
                        raise BadRequestException('Query filter value must be a string or list of strings')
                    conditions = self.perform_filter(conditions, key, item)
            elif isinstance(value, str):
                # Single value filter
                conditions = self.perform_filter(conditions, key, value)
            else:
                # Invalid
                raise BadRequestException('Query filter value must be a string or list of strings')

    def perform_filter(self, conditions: Any, key: str, value: Any) -> Any:
        condition = None
        value = unquote_plus(value)
        if value == '':
            raise BadRequestException('Filter key %s has no value' % key)

        # Check if this is a magic operator
        magic_operator_match = re.match('^(.+)__(.+)$', key)
        if magic_operator_match:
            key = magic_operator_match.group(1)
            operation = magic_operator_match.group(2)

            # Convert to decimal if this is a numeric >, <. >=, <= operation
            if value.isnumeric() and operation in self.NUMERIC_OPERATIONS:
                value = Decimal(value)

            # Fetch condition function from operation map
            func = self.operations().get(operation)

            if func is not None:
                # Run the condition function
                result = func(key, value)

                # If result is null, do not apply the condition
                if result is not None:
                    condition = result
            else:
                raise BadRequestException(f"Unsupported magic operator '{operation}")

        else:
            # No magic operator matches - using equals operation
            condition = self.equals(key, value)

        return self.And(conditions, condition)

    def multi_filter(self, user, filter_key, value):
        base_condition = None

        # Make sure a value was provided
        if not value:
            raise BadRequestException('No search values were provided')

        # Build pre-set filters
        base_condition = self.user_filters(user)

        # Build the multi-filters
        expressions = []

        if isinstance(value, list):
            if len(value) < 99:
                condition = self.And(base_condition, self.is_in(filter_key, value))
                expressions.append(condition)
            else:
                for i in range(0, len(value), 99):
                    condition = self.And(base_condition, self.is_in(filter_key, value[i:i + 99]))
                    expressions.append(condition)
        else:
            condition = self.And(base_condition, self.equals(filter_key, value))
            expressions.append(condition)

        return expressions
