import logging
import os
from pathlib import Path
import json
from subprocess import PIPE, STDOUT, run


def _run_command(shell_cmd):
    """Function accepts argument of shell command as `shell_cmd`
    Returns shell output formatted as list"""
    raw_out = run(shell_cmd, stdout=PIPE, stderr=STDOUT, shell=True, check=True)
    decoded_out = raw_out.stdout.decode().strip()
    exit_code = raw_out.returncode
    return exit_code, decoded_out


def load_cached_attributes(metadata_cache_path):
    """JSON load previous metadata to return as dict
    If no metadata found, return empty dict"""
    # Load metadata cache file from disk
    try:
        with open(metadata_cache_path) as cache_file:
            cached_files = json.load(cache_file)
    # Treat as new build
    except FileNotFoundError:
        cached_files = {}
    return cached_files


def create_file_and_attributes(attributes_dict):
    """Read metadata cache from previous run and write out all items to disk
    If short name in cache path differs from logged in user, update path for current user
    Creates files via mkfile -n, consuming no disk space but reporting defined byte size when
    queried by AutoPkg via os module for filesize comparison; writes any associated xattrs to files
    """
    # Python has no native support for extended attributes on macOS, so shell out to write attributes
    for i in attributes_dict:
        for dl_md in attributes_dict.get(i).get("download_metadata"):
            pathname = dl_md.get("pathname")
            etag = dl_md.get("etag")
            last_modified = dl_md.get("last_modified")
            dl_size_in_bytes = dl_md.get("dl_size_in_bytes")

            try:
                cache_path, cache_filename = os.path.split(pathname)
                logging.debug(f"Found previous cache path {cache_path}")
                # Replicate the previous download file with the metadata we know about it
                if not os.path.exists(cache_path):
                    path_to_create = Path(cache_path)
                    path_to_create.mkdir(parents=True, exist_ok=True)
                # Shell command to write file with specified size to path
                # If dl_size_in_bytes isn't valid, our _run_command will check and throw an exception
                _run_command(f"mkfile -n '{dl_size_in_bytes}' '{pathname}'")
                # Add metadata attributes or skip/report if None
                _run_command(
                    f"xattr -w com.github.autopkg.etag '{etag}' '{pathname}'"
                ) if etag else logging.info(
                    f"Skipping write of attribute 'etag' for {i}; key is missing"
                )
                _run_command(
                    f"xattr -w com.github.autopkg.last-modified '{last_modified}' '{pathname}'"
                ) if last_modified else logging.info(
                    f"Skipping write of attribute 'last_modified' for {i}; key is missing"
                )
                logging.info(
                    f"Wrote file with xattrs and byte size {dl_size_in_bytes} to {pathname}"
                )
            # Will hit this exception if "pathname" is NoneType when we try to split it
            except TypeError as e:
                logging.critical(
                    f"Issue when populating recipe '{i}' metadata!\nError is '{e}' for provided dict '{dl_md}'"
                )
