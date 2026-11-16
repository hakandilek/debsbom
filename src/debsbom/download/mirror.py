# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

"""
Resolver for packages of a remote APT repository, like a Debian mirror.

Packages are matched exactly by name, full version and (for binary packages) architecture.
Checksums of the requested packages are compared with the repository metadata. The .dsc
file of a source package is retrieved during resolution to verify its identity and its list
of files, but the repository metadata is **not authenticated** (its signatures are not
verified).
"""

from collections.abc import Mapping
import hashlib
import logging
import re
from urllib.parse import urlsplit

from debian.deb822 import Deb822

from ..apt.remote import (
    RemoteRepository,
    RepositoryError,
    RepositoryFile,
    RepositoryMetadataError,
    SourceRecord,
    parse_manifest,
)
from ..dpkg import package
from ..util.checksum import ChecksumAlgo, best_digest, calculate_checksums
from .resolver import NotFoundError, RemoteFile, ResolveError, Resolver

logger = logging.getLogger(__name__)

#: Maximum size of a .dsc file, which is retrieved during resolution.
MAX_DSC_SIZE = 4 * 1024 * 1024

_LABEL_MAX_LENGTH = 64


class MirrorResolveError(ResolveError):
    """The repository could not be used to resolve a package (except if it is not available)."""


class MirrorNotFoundError(MirrorResolveError, NotFoundError):
    """The package is not available in the repository."""


class MirrorIntegrityError(MirrorResolveError):
    """The data of the repository contradicts its metadata."""


def archive_label(url: str) -> str:
    """
    Name of the download directory of the files of a repository, derived from its URL,
    e.g. ``mirror_deb.debian.org_debian``. It only groups the files, it does not establish
    their origin.
    """
    parts = urlsplit(url)
    name = re.sub(r"[^A-Za-z0-9.-]+", "_", f"{parts.netloc}{parts.path}").strip("_.")
    if len(name) > _LABEL_MAX_LENGTH:
        digest = hashlib.sha256(url.encode()).hexdigest()[:8]
        name = f"{name[: _LABEL_MAX_LENGTH - 9]}_{digest}"
    return f"mirror_{name}" if name else "mirror"


def _describe(p: package.Package) -> str:
    if p.is_source():
        return f"source package {p.name} {p.version}"
    return f"binary package {p.name} {p.version} {p.architecture}"


def _mismatch(
    listed: Mapping[ChecksumAlgo, str], expected: Mapping[ChecksumAlgo, str]
) -> str | None:
    """
    Compare the strongest checksum both have in common. The result is final: on a mismatch,
    weaker checksums are not consulted. Returns None if there is no common checksum.
    """
    common = listed.keys() & expected.keys()
    if not common:
        return None
    algo = max(common)
    if listed[algo].lower() == expected[algo].lower():
        return None
    return f"{algo} is {listed[algo]}, expected {expected[algo]}"


def _data_mismatch(data: bytes, expected: Mapping[ChecksumAlgo, str]) -> str | None:
    """Verify data against the strongest expected checksum."""
    if not expected:
        return None
    algo, digest = best_digest(expected)
    return _mismatch(calculate_checksums(data, [algo]), {algo: digest})


class MirrorResolver(Resolver):
    """
    Resolve packages to the files of a remote APT repository.

    Binary package: the package with the same name, version and architecture is looked up
    in the ``Packages`` indexes. If the package has a checksum which can be compared with
    the metadata, candidates with a different checksum are ignored.

    Source package: the package with the same name and version is looked up in the
    ``Sources`` indexes. Candidates whose .dsc file has a different checksum than the
    package are ignored. The .dsc file of the first remaining candidate is retrieved and
    verified against the metadata and the package checksum. Its source name, version and
    list of files must match the ``Sources`` record. All files of the package are returned.
    Without a checksum of the package, the first candidate (in the order of the
    configured suites and components) is used.

    A package which is not listed (or only with a different checksum) is not found.
    Access, metadata, configuration and integrity problems are reported as errors.

    The results are not cached across runs, as the repository may change.

    :param repository: the repository to search
    :param archive_name: name of the download directory of the files, see
        :py:func:`archive_label`
    """

    def __init__(self, repository: RemoteRepository, archive_name: str | None = None):
        super().__init__()
        self.repository = repository
        self.archive_name = archive_name or archive_label(repository.url)

    def resolve(self, p: package.Package) -> list[RemoteFile]:
        try:
            if p.is_source():
                return self._resolve_source(p)
            return self._resolve_binary(p)
        except RepositoryError as e:
            raise MirrorResolveError(str(e)) from e

    def _remote_file(self, f: RepositoryFile) -> RemoteFile:
        return RemoteFile(
            checksums=dict(f.checksums),
            filename=f.name,
            archive_name=self.archive_name,
            downloadurl=self.repository.url_for(f.path),
            size=f.size,
        )

    def _not_found(self, p: package.Package, rejected: int) -> MirrorNotFoundError:
        reason = f" (ignored {rejected} with a different checksum)" if rejected else ""
        return MirrorNotFoundError(
            f"{_describe(p)} is not available in '{self.repository.url}'{reason}"
        )

    def _resolve_binary(self, p: package.Package) -> list[RemoteFile]:
        if not p.architecture:
            raise MirrorNotFoundError(f"{_describe(p)} cannot be looked up without architecture")
        expected = p.checksums
        rejected = 0
        for record in self.repository.find_binaries(p.name, str(p.version), p.architecture):
            problem = _mismatch(record.file.checksums, expected)
            if problem:
                logger.debug(f"Ignoring {_describe(p)} in '{record.index}': {problem}")
                rejected += 1
                continue
            if expected and not expected.keys() & record.file.checksums.keys():
                logger.debug(
                    f"No checksum of {_describe(p)} can be compared with '{record.index}', "
                    "the downloaded file is verified against both independently"
                )
            return [self._remote_file(record.file)]
        raise self._not_found(p, rejected)

    def _resolve_source(self, p: package.Package) -> list[RemoteFile]:
        expected = p.checksums
        if not expected:
            # see UpstreamResolver: a source package should be identifiable by name and version
            logger.info(
                f"no digest for {p}. Lookup will be imprecise, "
                f"the first package found in '{self.repository.url}' is used"
            )
        rejected = 0
        for record in self.repository.find_sources(p.name, str(p.version)):
            problem = _mismatch(record.dsc.checksums, expected)
            if problem is None:
                data = self._fetch_dsc(record)
                # the raw .dsc file identifies the package, also if signed differently
                problem = _data_mismatch(data, expected)
            if problem:
                logger.debug(f"Ignoring {_describe(p)} in '{record.index}': .dsc {problem}")
                rejected += 1
                continue
            self._check_dsc(record, data)
            dsc = record.dsc
            files = [dsc, *(f for f in record.files if f is not dsc)]
            return [self._remote_file(f) for f in files]
        raise self._not_found(p, rejected)

    def _fetch_dsc(self, record: SourceRecord) -> bytes:
        """Retrieve the .dsc file and verify it against the metadata."""
        dsc = record.dsc
        url = self.repository.url_for(dsc.path)
        if dsc.size > MAX_DSC_SIZE:
            raise MirrorResolveError(
                f"'{url}' exceeds the size limit of {MAX_DSC_SIZE} bytes of .dsc files"
            )
        try:
            data = self.repository.fetch(dsc.path, dsc.size)
        except RepositoryMetadataError as e:
            raise MirrorIntegrityError(
                f"'{url}' is larger than the {dsc.size} bytes listed in '{record.index}'"
            ) from e
        if len(data) != dsc.size:
            problem = f"size is {len(data)} bytes, expected {dsc.size}"
        else:
            problem = _data_mismatch(data, dsc.checksums)
        if problem:
            raise MirrorIntegrityError(f"'{url}' does not match '{record.index}': {problem}")
        return data

    def _check_dsc(self, record: SourceRecord, data: bytes) -> None:
        """
        Verify that the .dsc file describes the package of the record: the source name,
        the version and the files (with sizes and the strongest common checksums).
        """
        url = self.repository.url_for(record.dsc.path)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise MirrorIntegrityError(f"'{url}' is not valid UTF-8: {e}") from e
        # an OpenPGP signature is stripped, but not verified
        dsc = Deb822(text.splitlines())
        identity = (dsc.get("Source"), dsc.get("Version"))
        if identity != (record.name, record.version):
            raise MirrorIntegrityError(
                f"'{url}' describes source {identity[0]} {identity[1]}, but '{record.index}' "
                f"lists it for {record.name} {record.version}"
            )
        listed = {f.name: f for f in parse_manifest(dsc, f"'{url}'")}
        indexed = {f.name: f for f in record.files if f is not record.dsc}
        if listed.keys() != indexed.keys():
            raise MirrorIntegrityError(
                f"'{url}' lists the files {sorted(listed)}, but '{record.index}' lists "
                f"{sorted(indexed)}"
            )
        for name, f in indexed.items():
            if f.size != listed[name].size:
                raise MirrorIntegrityError(
                    f"'{url}' lists {name!r} with {listed[name].size} bytes, but "
                    f"'{record.index}' with {f.size} bytes"
                )
            if not f.checksums.keys() & listed[name].checksums.keys():
                raise MirrorIntegrityError(
                    f"'{url}' and '{record.index}' have no checksum of {name!r} in common"
                )
            problem = _mismatch(listed[name].checksums, f.checksums)
            if problem:
                raise MirrorIntegrityError(
                    f"'{url}' does not match '{record.index}' for {name!r}: {problem}"
                )
