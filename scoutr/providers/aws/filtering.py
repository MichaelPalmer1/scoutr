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

    def build_in_expr(self, attr, values, negate=False):
        start_index = 0
        end_index = 0
        conditions = None

        # IN expressions are limited to 100 items each
        for end_index in range(0, len(values), 100):
            # Create a slice of 100 items
            items = values[start_index:end_index]

            # Skip if no items are in this slice
            if not items:
                continue

            # Create IN expression
            expr = Attr(attr).is_in(items)
            if negate:
                expr = Not(expr)

            # Combine with conditions using OR
            if negate:
                conditions = self.And(conditions, expr)
            else:
                conditions = self.Or(conditions, expr)

            # Set new start index
            start_index = end_index

        # Add any extra items at the end
        if len(values[end_index:]) > 0:
            expr = Attr(attr).is_in(values[end_index:])
            if negate:
                conditions = self.And(conditions, Not(expr))
            else:
                conditions = self.Or(conditions, expr)

        return conditions

    def is_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        
        if not isinstance(values, list):
            raise Exception('In operation requires a list of values')

        return self.build_in_expr(attr, values)

    def not_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        return self.build_in_expr(attr, values, negate=True)

    def length(self, attr: str, value):
        return Attr(attr).size().eq(value)

    def length_greater_than(self, attr: str, value):
        return Attr(attr).size().gt(value)

    def length_greater_than_equal(self, attr: str, value):
        return Attr(attr).size().gte(value)

    def length_less_than(self, attr: str, value):
        return Attr(attr).size().lt(value)

    def length_less_than_equal(self, attr: str, value):
        return Attr(attr).size().lte(value)
