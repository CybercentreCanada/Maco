"""Custom model based on Maco's model."""

from __future__ import annotations

import pydantic

from maco import model


class MyCustomModel(model.ExtractorModel):
    """Custom model based on Maco's model."""

    class Other(pydantic.BaseModel):
        """Custom 'other' class."""

        key1: str
        key2: bool
        key3: int

    # set a custom class here as valid for the 'other' property
    other: Other | None = None
