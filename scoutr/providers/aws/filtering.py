import json

from boto3.dynamodb.conditions import Attr, Not

from scoutr.providers.base.filtering import Filtering


class AWSFiltering(Filtering):
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

    def equals(self, attr: str, value):
        return Attr(attr).eq(value)

    def not_equal(self, attr: str, value):
        return Attr(attr).ne(value)

    def contains(self, attr: str, value):
        return Attr(attr).contains(value)

    def not_contains(self, attr: str, value):
        return Not(Attr(attr).contains(value))

    def starts_with(self, attr: str, value):
        return Attr(attr).begins_with(value)

    def exists(self, attr: str, value):
        if value == "true":
            return Attr(attr).exists()
        elif value == "false":
            return Attr(attr).not_exists()
        else:
            raise Exception('Invalid value for exists operation')

    def greater_than(self, attr: str, value):
        return Attr(attr).gt(value)

    def less_than(self, attr: str, value):
        return Attr(attr).lt(value)

    def greater_than_equal(self, attr: str, value):
        return Attr(attr).gte(value)

    def less_than_equal(self, attr: str, value):
        return Attr(attr).lte(value)

    def between(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        if not len(values) == 2:
            raise Exception('Between operation requires two values')
        return Attr(attr).between(*values)

    def is_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        return Attr(attr).is_in(values)

    def not_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        return Not(Attr(attr).is_in(values))
