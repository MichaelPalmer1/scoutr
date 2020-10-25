from typing import get_type_hints, Dict, Any, List


class Model:
    def __init__(self, **kwargs):
        for attr, cls in get_type_hints(self).items():
            if attr not in kwargs:
                try:
                    value = cls()
                except TypeError:
                    value = None
                setattr(self, attr, value)
            else:
                value = kwargs[attr]

                try:
                    is_model_class = issubclass(cls, Model) and isinstance(value, dict)
                except TypeError:
                    is_model_class = False

                if is_model_class:
                    value = cls(**value)

                setattr(self, attr, value)

    @classmethod
    def attributes(cls) -> tuple:
        # attributes = inspect.getmembers(cls, lambda a: not (inspect.isroutine(a)))
        # return [a[0] for a in attributes if not (a[0].startswith('__') and a[0].endswith('__'))]
        return tuple(get_type_hints(cls).keys())

    def dict(self) -> Dict[str, Any]:
        output = {}
        for attribute in self.attributes():
            value = getattr(self, attribute)
            if isinstance(value, Model):
                value = value.dict()
            output[attribute] = value

        return output

    @classmethod
    def load(cls, data: Dict[str, Any]):
        return cls(**data)