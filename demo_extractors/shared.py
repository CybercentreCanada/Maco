from typing import Optional
import pydantic

from maco import model


class MyCustomModel(model.ExtractorModel):
    class Other(pydantic.BaseModel):
        key1: str
        key2: bool
        key3: int

    # set a custom class here as valid for the 'other' property
    other: Optional[Other] = None
