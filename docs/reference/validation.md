Data validation on all create and update calls is supported. In order to implement the validation, a dictionary
should be passed to the `validation` argument of the `create()` or `update()` methods of the provider.

## Required Fields

To require that specific fields exist in a CREATE request, specify those fields in the `required_fields` argument:

=== "Python"

    ```python
    api.create(request, data, required_fields=("product", "region"))
    ```

=== "Go"

    ```go
    requiredFields := []string{"product", "region"}

    api.Create(request, body, validation, requiredFields)
    ```

## Syntax

=== "Python"

    ```python
    FIELD_VALIDATION = {
        'field_name_1': lambda value, item, existing_item: callable_that_returns_a_bool,
        'field_name_2': lambda value, item, existing_item: callable_that_returns_a_dict,
        'field_name_3': callable_that_returns_a_bool,
        'field_name_4': callable_that_returns_a_dict
    }
    ```

=== "Go"

    ```go
    validation := map[string]utils.FieldValidation{
        "field1": func(value string, item map[string]string, existingItem map[string]string) (bool, string, error) {
            if value != "hello" {
                return false, fmt.Sprintf("Invalid value '%s' for attribute 'field1'", value), nil
            }

            return true, "", nil
        },
        "field2": func(value string, item map[string]string, existingItem map[string]string) (bool, string, error) {
            if value != "world" {
                return false, fmt.Sprintf("Invalid value '%s' for attribute 'field2'", value), nil
            }

            return true, "", nil
        },
    }
    ```

The key of each item in the dictionary should match a field name that you want to perform validation against. The
corresponding value for the key should be a callable that either returns a boolean or an object formatted as:

=== "Python"

    ```python
    {
        'result': boolean that indicates whether this field was valid or not,
        'message': 'custom error message to return to the user'
    }
    ```

=== "Go"
    The function should have an output of

    ```go
    (bool, string, error)
    ```

    For instance:

    ```go
    return true|false, "custom error message to return to the user", err|nil
    ```

The callable that you provide can either be a function or a lambda. The method signature of both options **must accept**
three arguments:

- `value` (Type: `string`) - Contains the input value for this field
- `item` (Type: `dict` / `map[string]interface{}`) - Contains the entire data object that was passed from the user
- `existing_item` (Type: `dict` / `map[string]interface{}`) - Contains the existing data object in the data table. This will only have a value on update calls.
    For create calls, this will be `None`.

## Example

=== "Python"

    ```python
    import re
    from scoutr.utils import value_in_set

    def validate_user(value, item, existing_item=None):
        if isinstance(existing_item, dict):
            item_type = existing_item.get('type')
        else:
            item_type = item.get('type')

        if not item_type:
            return {
                'result': False,
                'message': 'Type field is required'
            }

        if item_type == '1':
            return {
                'result': re.match('^\d{9}$', value),
                'message': 'Invalid user for type %s' % item_type
            }
        elif item_type == '2':
            return {
                'result': re.match('^.+@example.com$', value),
                'message': 'Invalid user for type %s' % item_type
            }
        else:
            return False

    FIELD_VALIDATION = {
        'user': validate_user,
        'type': lambda value, item, existing_item: value_in_set(
            value=value,
            valid_options{'1', '2'},
            option_name='type'
        ),
        'description': lambda value, item, existing_item: isinstance(value, str),
        'name': lambda value, item, existing_item: {
            'result': re.match('^\w+ \w+$', value),
            'message': 'Invalid name format'
        }
    }
    ```

=== "Go"

    ```go
    import (
        "fmt"
        "regexp"

        "github.com/MichaelPalmer1/scoutr-go/utils"
    )

    func validateUser(value string, item map[string]string, existingItem map[string]string) (bool, string, error) {
        var itemType string
        if existingItem != nil {
            itemType = existingItem["type"]
        } else {
            itemType = item["type"]
        }

        if _, ok := item["type"]; !ok {
            return false, "Type field is required", nil
        }

        if itemType == "Type1" {
            re := regexp.MustCompile("^\\d{10}$")
            if re.MatchString(value) {
                return true, "", nil
            } else {
                return false, "Value does not match pattern", nil
            }
        } else if itemType == "Type2" {
            re := regexp.MustCompile("^[a-z]+$")
            if re.MatchString(value) {
                return true, "", nil
            } else {
                return false, "Value does not match pattern", nil
            }
        } else {
            return false, "Validation failed", nil
        }
    }

    fieldValidation := map[string]utils.FieldValidation{
        "user": validateUser,
        "type": func(value string, item map[string]string, existingItem map[string]string) (bool, string, error) {
            validOptions := []string{"ABC", "DEF"}

            found := false
            for _, item := range validOptions {
                if item == value {
                    found = true
                    break
                }
            }

            if !found {
                return false, fmt.Sprintf("Invalid value. Supported options are %s", validOptions), nil
            }
        }
    }
    ```
