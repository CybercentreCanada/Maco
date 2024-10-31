# Maco - Malware config extractor framework

## Maco is a framework for ***ma***lware ***co***nfig extractors.

It aims to solve two problems:

- Define a standardize ontology (or model) for extractor output. This greatly helps for databasing extracted values.
- Provide a standard way of identifying which parsers to run and how to execute them.

## Maco components

- `model.py`
  - A data model for the common output of an extractor
- `extractor.py`
  - Base class for extractors to implement
- `collector.py`
  - Utilities for loading and running extractors
- `cli.py`
  - A CLI tool `maco` to assist with running your extractors locally
- `base_test.py`
  - Assist with writing unit tests for your extractors

**Note: If you're interested in using only the model in your project, you can `pip install maco-model` which is a smaller package containing only the model definition**

## Project Integrations 🛠️

This framework is actively being used by:

|                                                                                                              Project                                                                                                               | Description                                                                                                                                                                                                                                                   |                                                                                License                                                                                 |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|        <a href="https://cybercentrecanada.github.io/assemblyline4_docs/"><img src="https://images.weserv.nl/?url=cybercentrecanada.github.io/assemblyline4_docs/images/crane.png?v=4&h=100&w=100&fit=cover&maxage=7d"></a>         | A malware analysis platform that uses the MACO model to export malware configuration extractions into a parseable, machine-friendly format                                                                                                                    |       [![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline)](https://github.com/CybercentreCanada/assemblyline/blob/main/LICENSE.md)       |
|                                                                           [configextractor-py](https://github.com/CybercentreCanada/configextractor-py)                                                                            | A tool designed to run extractors from multiple frameworks and uses the MACO model for output harmonization                                                                                                                                                   | [![License](https://img.shields.io/github/license/CybercentreCanada/configextractor-py)](https://github.com/CybercentreCanada/configextractor-py/blob/main/LICENSE.md) |
| <a href="https://github.com/jeFF0Falltrades/rat_king_parser"><img src="https://images.weserv.nl/?url=raw.githubusercontent.com/jeFF0Falltrades/rat_king_parser/master/.github/logo.png?v=4&h=100&w=100&fit=cover&maxage=7d"/> </a> | A robust, multiprocessing-capable, multi-family RAT config parser/extractor that is compatible with MACO                                                                                                                                                      |      [![License](https://img.shields.io/github/license/jeFF0Falltrades/rat_king_parser)](https://github.com/jeFF0Falltrades/rat_king_parser/blob/master/LICENSE)       |
|                              <a href="https://github.com/apophis133/apophis-YARA-Rules"><img src="https://images.weserv.nl/?url=github.com/apophis133.png?v=4&h=100&w=100&fit=cover&maxage=7d"/> </a>                              | A parser/extractor repository that supports MACO for performing malware configuration extraction with YARA rule detection                                                                                                                                     |                                                                                                                                                                        |
|                           <a href="https://github.com/CAPESandbox/community"><img src="https://images.weserv.nl/?url=github.com/CAPESandbox.png?v=4&h=100&w=100&fit=cover&maxage=7d0&mask=circle"/> </a>                           | A parser/extractor repository containing MACO extractors that's authored by the CAPE community but is integrated in [CAPE](https://github.com/kevoreilly/CAPEv2) deployments.<br>**Note: These MACO extractors wrap and parse the original CAPE extractors.** |                  [![License](https://img.shields.io/badge/license-GPL--3.0-informational)](https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE)                   |

## Model Example

See [the model definition](https://github.com/CybercentreCanada/Maco/blob/0f447a66de5e5ce8770ef3fe2325aec002842e63/maco/model.py#L127) for all the supported fields.
You can use the model independently of the rest of the framework.
This is still useful for compatibility between systems!

```python
from maco import model
# 'family' is the only required property on the model
output = model.ExtractorModel(family="wanabee")
output.version = "2019"  # variant first found in 2019
output.category.extend([model.CategoryEnum.cryptominer, model.CategoryEnum.clickfraud])
output.http.append(model.ExtractorModel.Http(protocol="https",
                                             uri="https://bad-domain.com/c2_payload",
                                             usage="c2"))
output.tcp.append(model.ExtractorModel.Connection(server_ip="127.0.0.1",
                                           usage="ransom"))
output.campaign_id.append("859186-3224-9284")
output.inject_exe.append("explorer.exe")
output.binaries.append(
    output.Binary(
        data=b"sam I am",
        datatype=output.Binary.TypeEnum.config,
        encryption=output.Binary.Encryption(
            algorithm="rot26",
            mode="block",
        ),
    )
)
# data about the malware that doesn't fit the model
output.other["author_lunch"] = "green eggs and ham"
output.other["author_lunch_time"] = "3pm"
print(output.model_dump(exclude_defaults=True))

# Generated model
{
    'family': 'wanabee',
    'version': '2019',
    'category': ['cryptominer', 'clickfraud'],
    'campaign_id': ['859186-3224-9284'],
    'inject_exe': ['explorer.exe'],
    'other': {'author_lunch': 'green eggs and ham', 'author_lunch_time': '3pm'},
    'http': [{'uri': 'https://bad-domain.com/c2_payload', 'usage': 'c2', 'protocol': 'https'}],
    'tcp': [{'server_ip': '127.0.0.1', 'usage': 'ransom'}],
    'binaries': [{
        'datatype': 'config', 'data': b'sam I am',
        'encryption': {'algorithm': 'rot26', 'mode': 'block'}
    }]
}
```

And you can create model instances from dictionaries:

```python
from maco import model
output = {
    "family": "wanabee2",
    "version": "2022",
    "ssh": [
        {
            "username": "wanna",
            "password": "bee2",
            "hostname": "10.1.10.100",
        }
    ],
}
print(model.ExtractorModel(**output))

# Generated model
family='wanabee2' version='2022' category=[] attack=[] capability_enabled=[]
capability_disabled=[] campaign_id=[] identifier=[] decoded_strings=[]
password=[] mutex=[] pipe=[] sleep_delay=None inject_exe=[] other={}
binaries=[] ftp=[] smtp=[] http=[]
ssh=[SSH(username='wanna', password='bee2', hostname='10.1.10.100', port=None, usage=None)]
proxy=[] dns=[] tcp=[] udp=[] encryption=[] service=[] cryptocurrency=[]
paths=[] registry=[]
```

## Extractor Example

The following extractor will trigger on any file with more than 50 ELF sections,
and set some properties in the model.

Your extractors will do a better job of finding useful information than this one!

```python
class Elfy(extractor.Extractor):
    """Check basic elf property."""

    family = "elfy"
    author = "blue"
    last_modified = "2022-06-14"
    yara_rule = """
        import "elf"

        rule Elfy
        {
            condition:
                elf.number_of_sections > 50
        }
        """

    def run(
        self, stream: BytesIO, matches: List[yara.Match]
    ) -> Optional[model.ExtractorModel]:
        # return config model formatted results
        ret = model.ExtractorModel(family=self.family)
        # the list for campaign_id already exists and is empty, so we just add an item
        ret.campaign_id.append(str(len(stream.read())))
        return ret
```

## Writing Extractors

There are several examples that use Maco in the '`demo_extractors`' folder.

Some things to keep in mind:

- The Yara rule names must be prefixed with the extractor class name.
  - e.g. Class 'MyScript' has Yara rules named 'MyScriptDetect1' and 'MyScriptDetect2', not 'Detect1'
- You can load other scripts contained within the same folder via a Python relative import
  - See `complex.py` for details
- You can standardise your usage of the '`other`' dict
  - This is optional, see `limit_other.py` for details
  - Consider instead making a PR with the properties you are frequently using

# Requirements

Python 3.8+.

Install this package with `pip install maco`.

All required Python packages are in the `requirements.txt`.

# CLI Usage

```bash
> maco --help
usage: maco [-h] [-v] [--pretty] [--base64] [--logfile LOGFILE] [--include INCLUDE] [--exclude EXCLUDE] [-f] [--create_venv] extractors samples

Run extractors over samples.

positional arguments:
  extractors         path to extractors
  samples            path to samples

optional arguments:
  -h, --help         show this help message and exit
  -v, --verbose      print debug logging. -v extractor info, -vv extractor debug, -vvv cli debug
  --pretty           pretty print json output
  --base64           Include base64 encoded binary data in output (can be large, consider printing to file rather than console)
  --logfile LOGFILE  file to log output
  --include INCLUDE  comma separated extractors to run
  --exclude EXCLUDE  comma separated extractors to not run
  -f, --force        ignore yara rules and execute all extractors
  --create_venv      Creates venvs for every requirements.txt found (only applies when extractor path is a directory)
```

## CLI output example

The CLI is helpful for using your extractors in a standalone system, such as in a reverse engineering environment.

```bash
> maco demo_extractors/ /usr/lib --include Complex
extractors loaded: ['Complex']

complex by blue 2022-06-14 TLP:WHITE
This script has multiple yara rules and coverage of the data model.

path: /usr/lib/udev/hwdb.bin
run Complex extractor from rules ['ComplexAlt']
{"family": "complex", "version": "5", "decoded_strings": ["Paradise"],
"binaries": [{"datatype": "payload", "size": 9, "hex_sample": "736F6D652064617461", "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
"encryption": {"algorithm": "something"}}],
"http": [{"protocol": "https", "hostname": "blarg5.com", "path": "/malz/9956330", "usage": "c2"}],
"encryption": [{"algorithm": "sha256"}]}

path: /usr/lib/udev/hwdb.d/20-OUI.hwdb
run Complex extractor from rules ['ComplexAlt']
{"family": "complex", "version": "5", "decoded_strings": ["Paradise"],
"binaries": [{"datatype": "payload", "size": 9, "hex_sample": "736F6D652064617461", "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
"encryption": {"algorithm": "something"}}],
"http": [{"protocol": "https", "hostname": "blarg5.com", "path": "/malz/1986908", "usage": "c2"}],
"encryption": [{"algorithm": "sha256"}]}

path: /usr/lib/udev/hwdb.d/20-usb-vendor-model.hwdb
run Complex extractor from rules ['ComplexAlt']
{"family": "complex", "version": "5", "decoded_strings": ["Paradise"],
"binaries": [{"datatype": "payload", "size": 9, "hex_sample": "736F6D652064617461", "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
"encryption": {"algorithm": "something"}}],
"http": [{"protocol": "https", "hostname": "blarg5.com", "path": "/malz/1257481", "usage": "c2"}],
"encryption": [{"algorithm": "sha256"}]}


15884 analysed, 3 hits, 3 extracted
```

The demo extractors are designed to trigger when run over the '`demo_extractors`' folder.

e.g. `maco demo_extractors demo_extractors`
