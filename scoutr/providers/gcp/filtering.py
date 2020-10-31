import json

from google.cloud.firestore_v1 import Query, CollectionReference

from scoutr.exceptions import BadRequestException
from scoutr.providers.base.filtering import Filtering


class GCPFiltering(Filtering):
    def __init__(self, collection: CollectionReference):
        self.query = Query(collection)

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
        self.query = self.query.where(attr, '==', value)
        return self.query

    def not_equal(self, attr: str, value):
        self.query = self.query.where(attr, '!=', value)
        return self.query

    def greater_than(self, attr: str, value):
        self.query = self.query.where(attr, '>', value)
        return self.query

    def less_than(self, attr: str, value):
        self.query = self.query.where(attr, '<', value)
        return self.query

    def greater_than_equal(self, attr: str, value):
        self.query = self.query.where(attr, '>=', value)
        return self.query

    def less_than_equal(self, attr: str, value):
        self.query = self.query.where(attr, '<=', value)
        return self.query

    def between(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        if not len(values) == 2:
            raise Exception('Between operation requires two values')

        self.query = self.query.where(attr, '>=', values[0]).where(attr, '<=', values[1])
        return self.query

    def is_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        self.query = self.query.where(attr, 'in', values)
        return self.query

    def not_in(self, attr: str, value):
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        self.query = self.query.where(attr, 'not-in', values)
        return self.query
