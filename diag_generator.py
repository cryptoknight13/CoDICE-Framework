from io import TextIOWrapper
import json
import sys

key_minimum_padding: dict = {'ActiveBiosVersion': 4, 'RecoveryBiosVersion': 4}

DIAG_KEY_VALUE_FORMATTER:str = "{}/{}/ {}: {}{}\n"
DIAG_KEY_DICT_FORMATTER:str = "{}/{}/ {} : {{ \n{}{}}}{}\n"
DIAG_KEY_LIST_VALUE_FORMATTER: str = '{}/{}/ {} : \n {}{} \n'
DIAG_SIMPLE_LIST_FORMATTER: str = '{}[\n{}\n{}]'
DIAG_LIST_LIST_FORMATTER: str = '{}\n[{}]\n{}'
HEX_FORMATTER: str = "h'{}'"

def primitive_to_diag_format(object: object, key: str, justify: str) -> str:
    if key in key_minimum_padding and isinstance(object, str):
        object = object.ljust(key_minimum_padding.get(key), '0')
        pass

    tabs = "  " * justify

    if isinstance(object, str) and "0x" in str(object):
        return f"{tabs}{HEX_FORMATTER.format(str(object)[2:].lower())}" # Remove '0x" and formate in form of 'hAB1'
    elif isinstance(object, str):
        return f'{tabs}"{str(object)}"'
    elif isinstance(object, int):
        return f'{tabs}{str(object)}'

    
def json_to_diag(json, counter: int, justify: int) -> str:
    result: str = ""

    tabs = "  " * justify
        
    if isinstance(json, list):
        list_value = ""

        for index,object in enumerate(json):
            comma_char = "," if index < len(json) - 1 else ""
            new_line_char = "\n" if index < len(json) - 1 else ""

            if isinstance(object, list):
                list_value = list_value + json_to_diag(object, 0, (justify + 1)) + comma_char + new_line_char
            elif isinstance(object, dict):
            #list_value = list_value + DIAG_LIST_DICT_FORMATTER(tabs, json_to_diag(object, 0, (justify+2)), tabs, comma_char)
                list_value = list_value + tabs + " " + "{\n" + json_to_diag(object, 0, (justify+2)) + tabs + " " + "}" + comma_char+ new_line_char
            else:
                list_value = list_value + primitive_to_diag_format(object, None, justify + 1) + comma_char + new_line_char
                
        result = DIAG_SIMPLE_LIST_FORMATTER.format(tabs, list_value, tabs)

        return result


    if isinstance(json, dict):
        for index, (key, value) in enumerate(json.items()):
            comma_char = "," if index < len(json.items()) - 1 else "" ## Check whether we need to add comma at the end of line

            if isinstance(value, dict):
                result = result + DIAG_KEY_DICT_FORMATTER.format(tabs, key, counter, json_to_diag(value, 0, (justify + 1)), tabs, comma_char)
            elif isinstance(value, list):
                result = result + DIAG_KEY_LIST_VALUE_FORMATTER.format(tabs, key, counter, json_to_diag(value, None, (justify + 1)), comma_char)

            elif isinstance(value, str) or isinstance(value, int):
                result = result + DIAG_KEY_VALUE_FORMATTER.format(tabs, key, counter, primitive_to_diag_format(value, key, justify).strip(), comma_char)

            counter = counter + 1 ## This maintains the number fot tags.
 
    return result

if len(sys.argv) <= 1:
    print("Please provide json file as command line argument")
    exit()
output_filename = sys.argv[2] if (len(sys.argv) >= 3) else "diag_auto_gen.diag"

with open(sys.argv[1], "r") as file:
    json_string = json.load(file)

    result = "{\n" + json_to_diag(json_string, 0, 1) + "}"
    with open(output_filename, 'w') as file:
        file.write(result)
