from .exceptions import *
from os import stat
from os.path import exists
from typing import Dict, List, NoReturn, Union
import json
import logging

# Setup logger
logger = logging.getLogger(__name__)

class SchemaLoader:

    @classmethod
    def loads_json_file(cls, file_path: str) -> Union[Dict, List, NoReturn]:
        '''Loads json file.'''
        global logger
        _logger = logger.getChild(cls.__name__)

        if not exists(file_path):
            raise FileNotFoundError(file_path)
        elif stat(file_path).st_size == 0:
            raise EmptyFileError(file_path)
        else:
            _logger.debug(f"Reading file '{file_path}'...")
            with open(file_path, "r", encoding="utf-8") as f:
                return json.loads(f.read())