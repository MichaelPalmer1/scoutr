from typing import get_type_hints, Dict, Any


class Model:
    def __init__(self, *args, **kwargs):
        pass

    # def __init__(self, **kwargs):
    #     for attr, cls in get_type_hints(self.__class__).items():
    #         # Convert types
    #         try:
    #             if isinstance(cls, _GenericAlias):
    #                 if cls._name == 'List':
    #                     cls = list
    #                 elif cls._name == 'Dict':
    #                     cls = dict
    #         except TypeError as e:
    #             pass
    #
    #         if attr not in kwargs:
    #             args = []
    #             # If a default value is set, use that
    #             default_val = getattr(self, attr, None)
    #             if default_val is not None:
    #                 args.append(default_val)
    #
    #             try:
    #                 value = cls(*args)
    #             except TypeError:
    #                 value = None
    #             setattr(self, attr, value)
    #         else:
    #             value = kwargs[attr]
    #
    #             try:
    #                 is_model_class = issubclass(cls, Model) and isinstance(value, dict)
    #             except TypeError:
    #                 is_model_class = False
    #
    #             if is_model_class:
    #                 value = cls(**value)
    #
    #             setattr(self, attr, value)

    @classmethod
    def attributes(cls) -> tuple:
        # attributes = inspect.getmembers(cls, lambda a: not (inspect.isroutine(a)))
        # return [a[0] for a in attributes if not (a[0].startswith('__') and a[0].endswith('__'))]
        return tuple(get_type_hints(cls).keys())

    def dict(self) -> Dict[str, Any]:
        output = {}
        for attribute in self.attributes():
            value = getattr(self, attribute)
            if isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, Model):
                        value[i] = item.dict()
            elif isinstance(value, Model):
                value = value.dict()

            if value is not None:
                output[attribute] = value

        return output

    @classmethod
    def load(cls, data: Dict[str, Any]):
        valid_attributes = set(cls.attributes())

        # Compile list of required fields (fields that default to None)
        required_fields = set()
        for attr in valid_attributes:
            if getattr(cls, attr, None) is None:
                required_fields.add(attr)

        # Make sure required fields have values
        missing_fields = required_fields - set(data)
        if missing_fields:
            raise Exception(f'Missing required fields on {cls.__name__}: {missing_fields}')

        return cls(**data)
