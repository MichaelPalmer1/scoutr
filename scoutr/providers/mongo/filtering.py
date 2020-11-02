import json
from typing import Dict, Callable, Any

from scoutr.providers.base.filtering import Filtering


class MongoFiltering(Filtering):
    OPERATION_REGEX = 'regex'
    OPERATION_TYPE = 'type'
    OPERATION_HAS_ELEMENTS = 'haselements'

    @property
    def operations(self) -> Dict[str, Callable[[str, Any], Any]]:
        ops = super(MongoFiltering, self).operations
        ops.update({
            self.OPERATION_REGEX: self.regex,
            self.OPERATION_TYPE: self.is_type,
            self.OPERATION_HAS_ELEMENTS: self.has_elements
        })
        return ops

    def And(self, condition1, condition2):
        if condition1 and condition2:
            return {'$and': [condition1, condition2]}
        elif condition1:
            return condition1
        elif condition2:
            return condition2
        else:
            return None

    def Or(self, condition1, condition2):
        if condition1 and condition2:
            return {'$or': [condition1, condition2]}
        elif condition1:
            return condition1
        elif condition2:
            return condition2
        else:
            return None

    def equals(self, attr: str, value):
        return {
            attr: {'$eq': value}
        }

    def not_equal(self, attr: str, value):
        return {
            attr: {'$ne': value}
        }

    def contains(self, attr: str, value):
        return {
            attr: {'$regex': f'.*{value}.*'}
        }

    def not_contains(self, attr: str, value):
        return {
            attr: {'$regex': f'^(?:(?!{value}).)*$'}
        }

    def starts_with(self, attr: str, value):
        return {
            attr: {'$regex': f'^{value}.*'}
        }

    @staticmethod
    def has_elements(attr: str, value):
        values = json.loads(value)

        if isinstance(values, list):
            values = {
                '$in': values
            }
        elif not isinstance(values, dict):
            values = {
                '$eq': str(values)
            }
        return {
            attr: {'$elemMatch': values}
        }

    def greater_than(self, attr: str, value):
        return {
            attr: {'$gt': value}
        }

    def greater_than_equal(self, attr: str, value):
        return {
            attr: {'$gte': value}
        }

    def less_than(self, attr: str, value):
        return {
            attr: {'$lt': value}
        }

    def less_than_equal(self, attr: str, value):
        return {
            attr: {'$lte': value}
        }

    def between(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        if not len(values) == 2:
            raise Exception('Between operation requires two values')
        return {
            attr: {
                '$gte': values[0],
                '$lte': values[1]
            }
        }

    def is_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        return {
            attr: {'$in': values}
        }

    def not_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        return {
            attr: {'$nin': values}
        }

    def exists(self, attr: str, value):
        if value == "true":
            return {attr: {'$exists': True}}
        elif value == "false":
            return {attr: {'$exists': False}}
        else:
            raise Exception('Invalid value for exists operation')

    @staticmethod
    def is_type(attr: str, value):
        return {
            attr: {'$type': value}
        }

    @staticmethod
    def regex(attr: str, value):
        return {
            attr: {'$regex': value}
        }
