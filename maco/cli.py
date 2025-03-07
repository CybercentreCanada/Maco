"""CLI example of how extractors can be executed."""

import argparse
import base64
import binascii
import hashlib
import io
import json
import logging
import os
import sys
from importlib.metadata import version
from typing import BinaryIO, List, Tuple

import cart

from maco import collector

logger = logging.getLogger("maco.lib.cli")


def process_file(
    collected: collector.Collector,
    path_file: str,
    stream: BinaryIO,
    *,
    pretty: bool,
    force: bool,
    include_base64: bool,
):
    """Process a filestream with the extractors and rules.

    Args:
        collected (collector.Collector): a Collector instance
        path_file (str): path to sample to be analyzed
        stream (BinaryIO): binary stream to be analyzed
        pretty (bool): Pretty print the JSON output
        force (bool): Run all extractors regardless of YARA rule match
        include_base64 (bool): include base64'd data in output

    Returns:
        (dict): The output from the extractors analyzing the sample

    """
    unneutered = io.BytesIO()
    try:
        cart.unpack_stream(stream, unneutered)
    except Exception:
        # use original stream if anything goes wrong here
        # i.e. invalid/malformed cart
        pass
    else:
        # use unneutered stream
        stream = unneutered
    # unpack will read some bytes either way so reset position
    stream.seek(0)

    # find extractors that should run based on yara rules
    if not force:
        runs = collected.match(stream)
    else:
        # execute all extractors with no yara information
        # note - extractors may rely on a yara hit so this may cause errors
        runs = {x: [] for x in collected.extractors.keys()}
    if not runs:
        return

    # run extractor for the set of hits
    logger.info(f"path: {path_file}")
    ret = {}
    for extractor_name, hits in runs.items():
        # run and store results for extractor
        logger.info(f"run {extractor_name} extractor from rules {[x.rule for x in hits]}")
        try:
            resp = collected.extract(stream, extractor_name)
        except Exception as e:
            logger.exception(f"extractor error with {path_file} ({e})")
            resp = None
        # encode binary data so we can print as json
        if resp:
            for row in resp.get("binaries", []):
                row["sha256"] = hashlib.sha256(row["data"]).hexdigest()
                # number of bytes in the binary
                row["size"] = len(row["data"])
                # small sample of first part of binary
                row["hex_sample"] = binascii.hexlify(row["data"][:32]).decode("utf8").upper()
                if include_base64:
                    # this can be large
                    row["base64"] = base64.b64encode(row["data"]).decode("utf8")
                # do not print raw bytes to console
                row.pop("data")
        ret[extractor_name] = resp
        logger.info(json.dumps(resp, indent=2 if pretty else None))
    logger.info("")

    return ret


def process_filesystem(
    path_extractors: str,
    path_samples: str,
    include: List[str],
    exclude: List[str],
    *,
    pretty: bool,
    force: bool,
    include_base64: bool,
    create_venv: bool = False,
    skip_install: bool = False,
) -> Tuple[int, int, int]:
    """Process filesystem with extractors and print results of extraction.

    Returns:
        (Tuple[int, int, int]): Total number of analysed files, yara hits and successful maco extractions.
    """
    if force:
        logger.warning("force execute will cause errors if an extractor requires a yara rule hit during execution")
    collected = collector.Collector(
        path_extractors, include=include, exclude=exclude, create_venv=create_venv, skip_install=skip_install
    )

    logger.info(f"extractors loaded: {[x for x in collected.extractors.keys()]}\n")
    for _, extractor in collected.extractors.items():
        extractor_meta = extractor["metadata"]
        logger.info(
            f"{extractor_meta['family']} by {extractor_meta['author']}"
            f" {extractor_meta['last_modified']} {extractor_meta['sharing']}"
            f"\n{extractor_meta['description']}\n"
        )

    num_analysed = 0
    num_hits = 0
    num_extracted = 0
    if os.path.isfile(path_samples):
        # analyse a single file
        walker = [("", None, [path_samples])]
    elif os.path.isdir(path_samples):
        # load files from directory tree
        walker = os.walk(path_samples)
    else:
        logger.error(f"not file or folder: {path_samples}")
        exit(2)
    try:
        base_directory = os.path.abspath(path_samples)
        for path, _, files in walker:
            for file in files:
                num_analysed += 1
                path_file = os.path.abspath(os.path.join(path, file))
                if not path_file.startswith(base_directory):
                    logger.error(f"Attempted path traversal detected: {path_file}")
                    continue

                try:
                    with open(path_file, "rb") as stream:
                        resp = process_file(
                            collected,
                            path_file,
                            stream,
                            pretty=pretty,
                            force=force,
                            include_base64=include_base64,
                        )
                        if resp:
                            num_hits += 1
                            if any(x for x in resp.values()):
                                num_extracted += 1
                except Exception as e:
                    logger.exception(f"file error with {path_file} ({e})")
                    continue
    except:
        raise
    finally:
        logger.info("")
        logger.info(f"{num_analysed} analysed, {num_hits} hits, {num_extracted} extracted")
    return num_analysed, num_hits, num_extracted


def main():
    """Main block for CLI."""
    parser = argparse.ArgumentParser(description="Run extractors over samples.")
    parser.add_argument("extractors", type=str, help="path to extractors")
    parser.add_argument("samples", type=str, help="path to samples")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="print debug logging. -v extractor info, -vv extractor debug, -vvv cli debug",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty print json output")
    parser.add_argument(
        "--base64",
        action="store_true",
        help="Include base64 encoded binary data in output "
        "(can be large, consider printing to file rather than console)",
    )
    parser.add_argument("--logfile", type=str, help="file to log output")
    parser.add_argument("--include", type=str, help="comma separated extractors to run")
    parser.add_argument("--exclude", type=str, help="comma separated extractors to not run")
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="ignore yara rules and execute all extractors",
    )
    parser.add_argument(
        "--create_venv",
        action="store_true",
        help="Creates venvs for every requirements.txt found (only applies when extractor path is a directory). "
        "This runs much slower than the alternative but may be necessary "
        "when there are many extractors with conflicting dependencies.",
    )
    parser.add_argument(
        "--force_install",
        action="store_true",
        help="Force installation of Python dependencies for extractors (in both host and virtual environments).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"version: {version('maco')}",
        help="Show version of MACO",
    )

    args = parser.parse_args()
    inc = args.include.split(",") if args.include else []
    exc = args.exclude.split(",") if args.exclude else []

    # set up logging for lib, only show debug with 3+ verbose
    logger_lib = logging.getLogger("maco.lib")
    logger_lib.setLevel(logging.DEBUG if args.verbose > 2 else logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    logger_lib.addHandler(ch)

    # set up logging for extractor
    logger_ex = logging.getLogger("maco.extractor")
    if args.verbose == 0:
        logger_ex.setLevel(logging.WARNING)
    elif args.verbose == 1:
        logger_ex.setLevel(logging.INFO)
    else:
        logger_ex.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s, [%(levelname)s] %(module)s.%(funcName)s: %(message)s", datefmt="%Y-%m-%d (%H:%M:%S)"
    )
    ch.setFormatter(formatter)
    logger_ex.addHandler(ch)

    # log everything to file
    if args.logfile:
        logger = logging.getLogger("maco")
        logger_lib.setLevel(logging.DEBUG)
        fh = logging.FileHandler(args.logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    process_filesystem(
        args.extractors,
        args.samples,
        inc,
        exc,
        pretty=args.pretty,
        force=args.force,
        include_base64=args.base64,
        create_venv=args.create_venv,
        skip_install=not args.force_install,
    )


if __name__ == "__main__":
    main()
