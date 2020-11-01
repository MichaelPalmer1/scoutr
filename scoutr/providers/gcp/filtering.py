import json

from google.cloud.firestore_v1 import Query, CollectionReference

from scoutr.exceptions import BadRequestException
from scoutr.providers.base.filtering import Filtering


class GCPFiltering(Filtering):
    def __init__(self, collection: CollectionReference):
        self.collection = collection
        self.query = Query(collection)

    def And(self, condition1: Query, condition2: Query):
        if condition1 and condition2:
            return Query(
                self.collection,
                field_filters=condition1._field_filters + condition2._field_filters
            )
        elif condition1:
            return condition1
        elif condition2:
            return condition2

    def Or(self, condition1: Query, condition2: Query):
        if condition1 and condition2:
            return condition1 | condition2
        elif condition1:
            return condition1
        elif condition2:
            return condition2
        else:
            return None

    def equals(self, attr: str, value) -> Query:
        return Query(self.collection).where(attr, '==', value)

    def not_equal(self, attr: str, value) -> Query:
        return Query(self.collection).where(attr, '!=', value)

    def greater_than(self, attr: str, value) -> Query:
        return Query(self.collection).where(attr, '>', value)

    def less_than(self, attr: str, value) -> Query:
        return Query(self.collection).where(attr, '<', value)

    def greater_than_equal(self, attr: str, value) -> Query:
        return Query(self.collection).where(attr, '>=', value)

    def less_than_equal(self, attr: str, value) -> Query:
        return Query(self.collection).where(attr, '<=', value)

    def between(self, attr: str, value) -> Query:
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)
        if not len(values) == 2:
            raise BadRequestException('Between operation requires two values')

        return Query(self.collection).where(attr, '>=', values[0]).where(attr, '<=', values[1])

    def is_in(self, attr: str, value) -> Query:
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        return Query(self.collection).where(attr, 'in', values)

    def not_in(self, attr: str, value) -> Query:
        if isinstance(value, list):
            values = value
        else:
            values = json.loads(value)

        return Query(self.collection).where(attr, 'not-in', values)
