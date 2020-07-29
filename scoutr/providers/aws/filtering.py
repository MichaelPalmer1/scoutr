import json

from boto3.dynamodb.conditions import Attr, Not

from scoutr.providers.base.filtering import Filtering


class AWSFiltering(Filtering):
    def operations(self):
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

    def And(self, condition1, condition2):
        if condition1 and condition2:
            return condition1 & condition2
        elif condition1:
            return condition1
        elif condition2:
            return condition2
        else:
            return None

    def Or(self, condition1, condition2):
        if condition1 and condition2:
            return condition1 | condition2
        elif condition1:
            return condition1
        elif condition2:
            return condition2
        else:
            return None

    def equals(self, attr, value):
        return Attr(attr).eq(value)

    def not_equal(self, attr, value):
        return Attr(attr).ne(value)

    def contains(self, attr, value):
        return Attr(attr).contains(value)

    def not_contains(self, attr, value):
        return Not(Attr(attr).contains(value))

    def starts_with(self, attr, value):
        return Attr(attr).begins_with(value)

    def exists(self, attr, value):
        if value == "true":
            return Attr(attr).exists()
        elif value == "false":
            return Attr(attr).not_exists()
        else:
            raise Exception('Invalid value for exists operation')

    def greater_than(self, attr, value):
        return Attr(attr).gt(value)

    def less_than(self, attr, value):
        return Attr(attr).lt(value)

    def greater_than_equal(self, attr, value):
        return Attr(attr).gte(value)

    def less_than_equal(self, attr, value):
        return Attr(attr).lte(value)

    def between(self, attr, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        if not len(values) == 2:
            raise Exception('Between operation requires two values')
        return Attr(attr).between(*values)

    def is_in(self, attr, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        return Attr(attr).is_in(values)

    def not_in(self, attr, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        return Not(Attr(attr).is_in(values))
