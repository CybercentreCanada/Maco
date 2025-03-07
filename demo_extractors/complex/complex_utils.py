"""Example of a complex function invoked by the extractor."""

from typing import Dict


def getdata() -> Dict[str, int]:
    """This could be some complex and long function to support the main script.

    Returns:
        (Dict[str, int]): returns mock results
    """
    return {"result": 5}
