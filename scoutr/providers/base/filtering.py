import re
from abc import abstractmethod
from decimal import Decimal
from typing import Any, Optional, List, Dict
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
        return {
            self.OPERATION_EQUAL: self.equals,
            self.OPERATION_NOT_EQUAL: self.not_equal,
            self.OPERATION_CONTAINS: self.contains,
            self.OPERATION_NOT_CONTAINS: self.not_contains,
            self.OPERATION_STARTS_WITH: self.starts_with,
            self.OPERATION_EXISTS: self.exists,
            self.OPERATION_GREATER_THAN: self.greater_than,
            self.OPERATION_LESS_THAN: self.less_than,
            self.OPERATION_GREATER_THAN_EQUAL: self.greater_than_equal,
            self.OPERATION_LESS_THAN_EQUAL: self.less_than_equal,
            self.OPERATION_BETWEEN: self.between,
            self.OPERATION_IN: self.is_in,
            self.OPERATION_NOT_IN: self.not_in
        }

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

    def user_filters(self, user: Optional[User]) -> Any:
        if not user:
            return

        # Merge all possible values for this filter key together
        filters: Dict[str, List] = {}
        for item in user.filter_fields:
            filters.setdefault(item.field, list())
            filters[item.field].append(item.value)

        # Perform the filter
        conditions = None
        for key, values in filters.items():
            if len(values) == 1:
                # Perform a single query
                conditions = self.perform_filter(conditions, key, values[0])
            elif len(values) > 1:
                # Perform an OR query against all possible values for this key
                filter_conds = None
                for value in values:
                    filter_conds = self.Or(filter_conds, self.perform_filter(None, key, value))
                conditions = self.And(conditions, filter_conds)

        return conditions

    def filter(self, user: Optional[User], filters: dict = None):
        if filters is None:
            filters = {}

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

        return conditions

    def perform_filter(self, conditions: Any, key: str, value: Any) -> Any:
        condition = None
        if isinstance(value, str):
            value = unquote_plus(value)
            if value == '':
                raise BadRequestException('Filter key %s has no value' % key)

        # Check if this is a magic operator
        magic_operator_match = re.match('^(.+)__(.+)$', key)
        if magic_operator_match:
            key = magic_operator_match.group(1)
            operation = magic_operator_match.group(2)

            # Convert to decimal if this is a numeric operation
            if isinstance(value, str) and value.isnumeric() and operation in self.NUMERIC_OPERATIONS:
                value = Decimal(value)

            # Fetch condition function from operation map
            func = self.operations().get(operation)

            try:
                if func is None:
                    raise NotImplementedError

                # Run the condition function
                result = func(key, value)

                # If result is null, do not apply the condition
                if result is not None:
                    condition = result
            except NotImplementedError:
                raise BadRequestException(f"Provider does not support magic operator '{operation}")

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
