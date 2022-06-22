# Maco - Malware config extractor framework

Maco is a framework for **ma**lware **co**nfig extractors.

We made it because we need to share extractors and outputs between multiple different systems.

Maco provides
* model.py
    * a data model for common output of an extractor
* extractor.py
    * base class for extractors to implement
* collector.py
    * utilities for loading and running extractors
* cli.py
    * a cli tool `maco` to assist with running your extractors locally
* base_test.py
    * assist with writing unit tests for your extractors


## Model Example

You can use the model independently of the rest of the framework. 
This is still useful for compatibility between systems!

```
from maco import model
# 'family' is the only required property on the model
output = model.ExtractorModel(family="wanabee")
output.version = "2019"  # variant first found in 2019
output.category.extend([model.CategoryEnum.cryptominer, model.CategoryEnum.clickfraud])
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
print(output.dict(exclude_defaults=True))

# Generated model
{
    'family': 'wanabee', 
    'version': '2019', 
    'category': ['cryptominer', 'clickfraud'], 
    'campaign_id': ['859186-3224-9284'], 
    'inject_exe': ['explorer.exe'], 
    'other': {'author_lunch': 'green eggs and ham', 'author_lunch_time': '3pm'}, 
    'binaries': [{
        'datatype': 'config', 'data': b'sam I am', 
        'encryption': {'algorithm': 'rot26', 'mode': 'block'}
    }]
}
```

And you can create model instances from dictionaries

```
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

The following extractor will trigger on any file with more than 50 elf sections,
and set some properties in the model.

Your extractors will do a better job of finding useful information than this one!

```
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

There are several examples that use Maco in the 'demo_extractors' folder.

Some things to keep in mind
* The yara rule names must be prefixed with the extractor class name.
    * e.g. class 'MyScript' has yara rules named 'MyScriptDetect1' and 'MyScriptDetect2', not 'Detect1'
* You can load other scripts contained within the same folder via a python relative import
    * see `complex.py` for details
* You can standardise your usage of the 'other' dict
    * this is optional, see `limit_other.py` for details
    * consider instead making a PR with the properties you are frequently using

# Requirements


Python 3.7+

All required python packages are in the requirements.txt


<!-- TODO update instructions when this is on pypi -->
Install this package with `pip`.

# Usage


```
> maco --help
usage: maco [-h] [-v] [--pretty] [--logfile LOGFILE] [--whitelist WHITELIST]
            [--blacklist BLACKLIST]
            extractors samples

Run extractors over samples.

positional arguments:
  extractors            path to extractors
  samples               path to samples

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         print debug logging. -v extractor info, -vv extractor debug, -vvv
                        cli debug
  --pretty              pretty print json output
  --logfile LOGFILE     file to log output
  --whitelist WHITELIST
                        comma separated extractors to run
  --blacklist BLACKLIST
                        comma separated extractors to not run
```

```
> maco demo_extractors/ /usr/lib --whitelist Complex
extractors loaded: ['Complex']

complex by blue 2022-06-14 TLP:WHITE
This script has multiple yara rules and coverage of the data model.

path: /usr/lib/udev/hwdb.bin
run Complex extractor from rules ['ComplexAlt']
{"family": "complex", "version": "5", "decoded_strings": ["Paradise"], 
"binaries": [{"datatype": "payload", "data": "c29tZSBkYXRh", 
"encryption": {"algorithm": "something"}}], 
"http": [{"protocol": "https", "hostname": "blarg5.com", "path": "/malz/9956330", "usage": "c2"}], 
"encryption": [{"algorithm": "sha256"}]}

path: /usr/lib/udev/hwdb.d/20-OUI.hwdb
run Complex extractor from rules ['ComplexAlt']
{"family": "complex", "version": "5", "decoded_strings": ["Paradise"], 
"binaries": [{"datatype": "payload", "data": "c29tZSBkYXRh", 
"encryption": {"algorithm": "something"}}], 
"http": [{"protocol": "https", "hostname": "blarg5.com", "path": "/malz/1986908", "usage": "c2"}], 
"encryption": [{"algorithm": "sha256"}]}

path: /usr/lib/udev/hwdb.d/20-usb-vendor-model.hwdb
run Complex extractor from rules ['ComplexAlt']
{"family": "complex", "version": "5", "decoded_strings": ["Paradise"], 
"binaries": [{"datatype": "payload", "data": "c29tZSBkYXRh", 
"encryption": {"algorithm": "something"}}], 
"http": [{"protocol": "https", "hostname": "blarg5.com", "path": "/malz/1257481", "usage": "c2"}], 
"encryption": [{"algorithm": "sha256"}]}


15884 analysed, 3 hits, 3 extracted
```

The demo extractors are designed to trigger when run over the 'demo_extractors' folder.
e.g. `maco demo_extractors demo_extractors`
