from enum import Enum

from .model.human_formatter import HumanFormatter, BaseFormatter
from .model.machine_formatter import MachineFormatter
from .model import ExtractorModel

class FormatterOption(Enum):
    HUMAN = 1
    MACHINE = 2
    CUSTOM = 9

class InvalidFormatterException(Exception):
    pass

class Formatter:
    formatter: BaseFormatter

    def __init__(self,  type: FormatterOption, 
                        custom_formatter: BaseFormatter = None):
        
        if type == FormatterOption.CUSTOM:
            if not isinstance(custom_formatter, BaseFormatter):
                raise InvalidFormatterException("Custom formatter must inherit from BaseFormatter")
            self.formatter = custom_formatter()

        elif type == FormatterOption.MACHINE:
            self.formatter = MachineFormatter()
        
        elif type == FormatterOption.HUMAN:
            self.formatter = HumanFormatter()
        

    def format(self, model: ExtractorModel):
        return self.formatter.format(model)