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


<!-- TODO update instructions when this is on pypi -->
Install this package with `pip`.

Run `maco <extractors_folder> <folder_to_analyse>` to run your extractors locally.

The demo extractors are designed to trigger when run over the 'demo_extractors' folder.
e.g. `maco demo_extractors demo_extractors`

Check `maco --help` for more options.

Extractors are not intended to be installed via a python package manager.
They are expected to be present on disk in a known folder.
This is so that extractors can be easily loaded/updated via Kubernetes or otherwise.
