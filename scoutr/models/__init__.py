from typing import get_type_hints, Dict, Any, _GenericAlias


class Model:
    def __init__(self, **kwargs):
        for attr, cls in get_type_hints(self.__class__).items():
            # Convert types
            try:
                if isinstance(cls, _GenericAlias):
                    if cls._name == 'List':
                        cls = list
                    elif cls._name == 'Dict':
                        cls = dict
            except TypeError:
                pass

            # Check if attribute is not in kwargs
            if attr not in kwargs:
                # If a default value is set, use that
                args = []
                default_val = getattr(self, attr, None)
                if default_val is not None:
                    args.append(default_val)

                # Try to initialize the value
                try:
                    value = cls(*args)
                except TypeError:
                    value = None
            else:
                # Set value from kwargs
                value = kwargs[attr]

                # Detect if this is a Model class
                try:
                    is_model_class = issubclass(cls, Model) and isinstance(value, dict)
                except TypeError:
                    is_model_class = False

                # Run Modal class constructor
                if is_model_class:
                    value = cls(**value)

            # Set the attribute
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
    def load(cls, data: Dict[str, Any], skip_validation=False):
        model = cls(**data)
        if not skip_validation:
            model.validate()

        return model

    def validate(self):
        valid_attributes = set(self.attributes())

        # Compile list of required fields (fields that default to None)
        required_fields = set()
        for attr in valid_attributes:
            if getattr(self.__class__, attr, None) is None:
                required_fields.add(attr)

        # Compile list of fields that have values
        missing_fields = set()
        for attr in valid_attributes:
            if getattr(self, attr, None) is None:
                missing_fields.add(attr)

        # Make sure required fields have values
        if missing_fields:
            raise Exception(f'Missing required fields on {self.__class__.__name__}: {missing_fields}')
