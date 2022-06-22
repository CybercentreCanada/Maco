from io import BytesIO
from typing import Dict, List, Optional

import yara

from maco import extractor, model

from . import complex_utils


class Complex(extractor.Extractor):
    """This script has multiple yara rules and coverage of the data model."""

    family = "complex"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        private rule ComplexSubtext
        {
            strings:
                $self_trigger = "self_trigger"
            condition:
                $self_trigger
        }
        rule Complex
        {
            strings:
                $self_trigger = "Complex"
                $my_hex_string = { E2 34 A1 C8 23 FB }

            condition:
                ($self_trigger or $my_hex_string) and ComplexSubtext
        }
        rule ComplexAlt
        {
            strings:
                $self_trigger = "Paradise"

            condition:
                $self_trigger
        }
        """

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[model.ExtractorModel]:
        self.logger.info("starting run")
        self.logger.debug(f"{[x.rule for x in matches]=}")
        data = stream.read()
        if not data:
            return
        # this is where you would do some processing on the file
        data_len = len(data)
        other = complex_utils.getdata()["result"]
        self.logger.debug("got data from lib")
        # example - accessing yara strings
        strings = {y[2].decode("utf8") for x in matches for y in x.strings}
        self.logger.debug(f"{strings=}")
        # construct model of results
        tmp = model.ExtractorModel(family=self.family)
        tmp.decoded_strings = strings
        tmp.version = "5"
        tmp.http.append(
            tmp.Http(
                protocol="https",
                hostname=f"blarg{other}.com",
                path=f"/malz/{data_len}",
                usage="c2",
            )
        )

        tmp.encryption.append(tmp.Encryption(algorithm="sha256"))
        tmp.binaries.append(
            tmp.Binary(
                data=b"some data",
                datatype=tmp.Binary.TypeEnum.payload,
                encryption=tmp.Binary.Encryption(algorithm="something"),
            )
        )
        return tmp
