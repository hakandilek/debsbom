# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import hashlib
import io
import json
import logging
import lzma
from pathlib import Path
import sys
from urllib.parse import quote

import jsonschema
import pytest
import requests

from debsbom import schema
from debsbom.apt.remote import RemoteRepository
from debsbom.cli import setup_parser
from debsbom.commands import download as download_cmd
from debsbom.download import mirror
from debsbom.download.download import DownloadStatus, PackageDownloader
from debsbom.download.mirror import (
    MirrorIntegrityError,
    MirrorNotFoundError,
    MirrorResolveError,
    MirrorResolver,
    archive_label,
)
from debsbom.download.resolver import (
    FallbackResolver,
    NotFoundError,
    PackageResolverCache,
    PersistentResolverCache,
    RemoteFile,
    Resolver,
)
from debsbom.dpkg.package import BinaryPackage, SourcePackage
from debsbom.repack.merger import SourceArchiveMerger
from debsbom.snapshot.client import UPSTREAM_ARCHIVE_ORDER, UpstreamResolver
from debsbom.util.checksum import ChecksumAlgo

MD5 = ChecksumAlgo.MD5SUM
SHA1 = ChecksumAlgo.SHA1SUM
SHA256 = ChecksumAlgo.SHA256SUM
SHA512 = ChecksumAlgo.SHA512SUM

ROOT = "https://mirror.example.org/debian"
LABEL = "mirror_mirror.example.org_debian"
SOURCES = "dists/trixie/main/source/Sources"
ORIG = b"upstream sources"
DEBIAN = b"packaging"


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


LISTS = {"Files": md5, "Checksums-Sha1": sha1, "Checksums-Sha256": sha256}
BINARY_CHECKSUMS = {"MD5sum": md5, "SHA1": sha1, "SHA256": sha256}


def manifest(files: dict[str, bytes], lists) -> list[str]:
    lines = []
    for field in lists:
        lines.append(f"{field}:")
        lines += [f" {LISTS[field](d)} {len(d)} {n}" for n, d in files.items()]
    return lines


def make_dsc(
    name="foo",
    version="1.0-1",
    files=None,
    lists=("Checksums-Sha1", "Checksums-Sha256", "Files"),
    signature=None,
    source=None,
):
    """Create a .dsc file, optionally with a (fake) OpenPGP signature."""
    if files is None:
        files = default_files(name, version)
    lines = [
        "Format: 3.0 (quilt)",
        f"Source: {source or name}",
        f"Binary: {name}",
        "Architecture: any",
        f"Version: {version}",
        "Maintainer: Jörg Müller <jm@example.org>",
        *manifest(files, lists),
    ]
    text = "\n".join(lines) + "\n"
    if signature:
        text = (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
            f"{text}\n-----BEGIN PGP SIGNATURE-----\n\n{signature}\n-----END PGP SIGNATURE-----\n"
        )
    return text.encode()


def no_epoch(version: str) -> str:
    return version.split(":")[-1]


def default_files(name, version):
    upstream = no_epoch(version).rsplit("-", 1)[0]
    return {
        f"{name}_{upstream}.orig.tar.gz": ORIG,
        f"{name}_{no_epoch(version)}.debian.tar.xz": DEBIAN,
    }


class Repo:
    """A compact APT repository, served by the fake HTTP adapter or stored in a directory."""

    def __init__(self):
        self.tree: dict[str, bytes] = {}
        self.indexes: dict[str, list[str]] = {}

    def add_source(
        self,
        name="foo",
        version="1.0-1",
        files=None,
        *,
        index=SOURCES,
        directory=None,
        dsc=None,
        lists=("Files", "Checksums-Sha256"),
    ) -> bytes:
        if files is None:
            files = default_files(name, version)
        if directory is None:
            directory = f"pool/main/{name[0]}/{name}"
        if dsc is None:
            dsc = make_dsc(name, version, files)
        allfiles = {f"{name}_{no_epoch(version)}.dsc": dsc, **files}
        for n, d in allfiles.items():
            self.tree[f"{directory}/{n}".removeprefix("./")] = d
        paragraph = [
            f"Package: {name}",
            f"Binary: {name}",
            f"Version: {version}",
            "Maintainer: Jörg Müller <jm@example.org>",
            "Format: 3.0 (quilt)",
            f"Directory: {directory}",
            *manifest(allfiles, lists),
        ]
        self.indexes.setdefault(index, []).append("\n".join(paragraph) + "\n")
        return dsc

    def add_binary(
        self,
        name="foo",
        version="1.0-1",
        arch="amd64",
        data=None,
        *,
        index=None,
        filename=None,
        checksums=("MD5sum", "SHA256"),
    ) -> bytes:
        if index is None:
            index = f"dists/trixie/main/binary-{arch}/Packages"
        if filename is None:
            filename = f"pool/main/{name[0]}/{name}/{name}_{no_epoch(version)}_{arch}.deb"
        if data is None:
            data = f"{name} {version} {arch}".encode()
        self.tree[filename] = data
        paragraph = [
            f"Package: {name}",
            f"Version: {version}",
            f"Architecture: {arch}",
            "Maintainer: Jörg Müller <jm@example.org>",
            f"Filename: {filename}",
            f"Size: {len(data)}",
            *(f"{c}: {BINARY_CHECKSUMS[c](data)}" for c in checksums),
            "Description: test package ✓",
        ]
        self.indexes.setdefault(index, []).append("\n".join(paragraph) + "\n")
        return data

    def files(self) -> dict[str, bytes]:
        tree = dict(self.tree)
        for path, paragraphs in self.indexes.items():
            data = "\n".join(paragraphs).encode()
            tree[f"{path}.xz"] = lzma.compress(data, format=lzma.FORMAT_XZ)
        return tree

    def publish(self, adapter, root=ROOT):
        for path, data in self.files().items():
            adapter.add(f"{root}/{quote(path, safe='/')}", data)

    def write(self, directory: Path) -> str:
        for path, data in self.files().items():
            target = directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return directory.as_uri()


@pytest.fixture
def make_resolver(fake_http):
    session, _ = fake_http

    def make(suites=("trixie",), components=("main",), architectures=(), url=ROOT):
        return MirrorResolver(RemoteRepository(session, url, suites, components, architectures))

    return make


@pytest.fixture
def adapter(fake_http):
    return fake_http[1]


def binary(name="foo", version="1.0-1", arch="amd64", checksums=None):
    return BinaryPackage(name=name, version=version, architecture=arch, checksums=checksums)


def source(name="foo", version="1.0-1", checksums=None):
    return SourcePackage(name=name, version=version, checksums=checksums)


def url(path: str) -> str:
    return f"{ROOT}/{path}"


@pytest.mark.parametrize(
    "root,label",
    [
        (ROOT, LABEL),
        ("https://deb.debian.org/debian-security", "mirror_deb.debian.org_debian-security"),
        ("http://[::1]:8080", "mirror_1_8080"),
        ("file:///srv/apt/repo+1", "mirror_srv_apt_repo_1"),
        ("file://", "mirror"),
    ],
)
def test_archive_label(root, label):
    assert archive_label(root) == label
    assert label not in UPSTREAM_ARCHIVE_ORDER


def test_archive_label_long(tmp_path):
    long_a = f"{ROOT}/{'a' * 100}/x"
    long_b = f"{ROOT}/{'a' * 100}/y"
    label = archive_label(long_a)
    assert archive_label(long_a) == label
    assert label != archive_label(long_b)
    assert len(label) <= len("mirror_") + 64
    # the label is a single, safe directory name
    downloader = PackageDownloader(tmp_path)
    rf = RemoteFile(checksums={}, filename="foo.deb", archive_name=label, downloadurl=long_a)
    target = downloader._target_path(binary(), rf)
    assert target == (tmp_path / "binaries" / label / "foo.deb").resolve()


def test_no_request_on_construction(make_resolver, adapter):
    resolver = make_resolver()
    assert resolver.archive_name == LABEL
    assert type(resolver.cache) is PackageResolverCache
    assert adapter.requests == []


def test_binary(make_resolver, adapter):
    repo = Repo()
    data = repo.add_binary()
    repo.add_binary(version="1.0-2")
    repo.publish(adapter)
    files = make_resolver().resolve(binary())
    assert files == [
        RemoteFile(
            checksums={MD5: md5(data), SHA256: sha256(data)},
            filename="foo_1.0-1_amd64.deb",
            archive_name=LABEL,
            downloadurl=url("pool/main/f/foo/foo_1.0-1_amd64.deb"),
            size=len(data),
        )
    ]


@pytest.mark.parametrize(
    "name,version,arch,found",
    [
        ("foo", "1:2.0-1", "amd64", True),
        ("foo", "2.0-1", "amd64", False),
        ("foo", "0:2.0-1", "amd64", False),
        ("bar", "1.0-1+b1", "amd64", True),
        ("bar", "1.0-1", "amd64", False),
        # an 'Architecture: all' package is not a replacement for a native one
        ("baz", "1.0-1", "amd64", False),
        ("qux", "1.0-1", "amd64", True),
        ("qux", "1.0-1", "arm64", False),
        ("quux", "1.0-1", "amd64", False),
    ],
)
def test_binary_exact_identity(make_resolver, adapter, name, version, arch, found):
    repo = Repo()
    repo.add_binary("foo", "1:2.0-1")
    repo.add_binary("bar", "1.0-1+b1")
    repo.add_binary("baz", "1.0-1", "all", index="dists/trixie/main/binary-amd64/Packages")
    repo.add_binary("qux", "1.0-1")
    repo.publish(adapter)
    resolver = make_resolver()
    if found:
        (rf,) = resolver.resolve(binary(name, version, arch))
        assert rf.filename == f"{name}_{no_epoch(version)}_{arch}.deb"
    else:
        with pytest.raises(MirrorNotFoundError, match="is not available"):
            resolver.resolve(binary(name, version, arch))


def test_binary_actual_filename(make_resolver, adapter):
    repo = Repo()
    repo.add_binary(filename="./pool/extra/foo-renamed_1.0-1+custom_amd64.deb")
    repo.publish(adapter)
    (rf,) = make_resolver().resolve(binary())
    assert rf.filename == "foo-renamed_1.0-1+custom_amd64.deb"
    assert rf.downloadurl == url("pool/extra/foo-renamed_1.0-1%2Bcustom_amd64.deb")


DATA = b"foo 1.0-1 amd64"
OTHER = b"other data"


@pytest.mark.parametrize(
    "checksums,found",
    [
        ({SHA256: sha256(DATA)}, True),
        ({SHA256: sha256(DATA).upper()}, True),
        ({SHA256: sha256(OTHER)}, False),
        ({MD5: md5(DATA)}, True),
        ({MD5: md5(OTHER)}, False),
        # the strongest common checksum decides
        ({MD5: md5(OTHER), SHA256: sha256(DATA)}, True),
        ({MD5: md5(DATA), SHA256: sha256(OTHER)}, False),
        # no common checksum: the downloaded file is verified later
        ({SHA512: sha512(OTHER)}, True),
    ],
)
def test_binary_checksums(make_resolver, adapter, checksums, found):
    repo = Repo()
    repo.add_binary(data=DATA)
    repo.publish(adapter)
    resolver = make_resolver()
    if found:
        assert len(resolver.resolve(binary(checksums=checksums))) == 1
    else:
        with pytest.raises(MirrorNotFoundError, match="ignored 1 with a different checksum"):
            resolver.resolve(binary(checksums=checksums))


def test_binary_candidates_in_order(make_resolver, adapter):
    repo = Repo()
    repo.add_binary(data=DATA, index="dists/bookworm/main/binary-amd64/Packages")
    repo.add_binary(
        data=OTHER,
        index="dists/trixie/contrib/binary-amd64/Packages",
        filename="pool/contrib/f/foo/foo_1.0-1_amd64.deb",
    )
    repo.publish(adapter)
    resolver = make_resolver(suites=["trixie", "bookworm"], components=["contrib", "main"])
    (rf,) = resolver.resolve(binary())
    assert rf.downloadurl == url("pool/contrib/f/foo/foo_1.0-1_amd64.deb")
    (rf,) = resolver.resolve(binary(checksums={SHA256: sha256(DATA)}))
    assert rf.downloadurl == url("pool/main/f/foo/foo_1.0-1_amd64.deb")
    with pytest.raises(MirrorNotFoundError, match="ignored 2"):
        resolver.resolve(binary(checksums={SHA256: sha256(b"unknown")}))


def test_binary_architecture_all(make_resolver, adapter):
    repo = Repo()
    # the packages are listed in the indexes of the native architectures
    repo.tree["dists/trixie/Release"] = (
        b"Architectures: amd64 arm64 all\nNo-Support-for-Architecture-all: Packages\n"
    )
    repo.add_binary("data", "1.0-1", "all", index="dists/trixie/main/binary-arm64/Packages")
    repo.publish(adapter)
    (rf,) = make_resolver().resolve(binary("data", arch="all"))
    assert rf.downloadurl == url("pool/main/d/data/data_1.0-1_all.deb")
    assert url("dists/trixie/main/binary-all/Packages.xz") not in adapter.urls


def test_binary_architecture_all_requires_configuration(make_resolver, adapter):
    repo = Repo()
    repo.add_binary("data", "1.0-1", "all", index="dists/trixie/main/binary-amd64/Packages")
    repo.publish(adapter)
    with pytest.raises(MirrorResolveError, match="configure the architectures") as e:
        make_resolver().resolve(binary("data", arch="all"))
    assert not isinstance(e.value, NotFoundError)
    # an explicitly configured architecture is searched
    (rf,) = make_resolver(architectures=["amd64"]).resolve(binary("data", arch="all"))
    assert rf.filename == "data_1.0-1_all.deb"


def test_binary_without_architecture(make_resolver, adapter):
    with pytest.raises(MirrorNotFoundError, match="without architecture"):
        make_resolver().resolve(binary(arch=None))
    assert adapter.requests == []


@pytest.mark.parametrize(
    "version,files",
    [
        # native
        ("1.0", {"foo_1.0.tar.xz": ORIG}),
        # quilt
        ("1.0-1", None),
        # multiple upstream tarballs
        (
            "1.0-1",
            {
                "foo_1.0.orig.tar.gz": ORIG,
                "foo_1.0.orig-docs.tar.gz": b"docs",
                "foo_1.0-1.debian.tar.xz": DEBIAN,
            },
        ),
        # upstream signature
        (
            "1.0-1",
            {
                "foo_1.0.orig.tar.gz": ORIG,
                "foo_1.0.orig.tar.gz.asc": b"signature",
                "foo_1.0-1.debian.tar.xz": DEBIAN,
            },
        ),
    ],
)
def test_source_bundle(make_resolver, adapter, version, files):
    repo = Repo()
    dsc = repo.add_source(version=version, files=files)
    repo.publish(adapter)
    result = make_resolver().resolve(source(version=version, checksums={SHA256: sha256(dsc)}))
    files = files or default_files("foo", version)
    expected = {f"foo_{version}.dsc": dsc, **files}
    assert [rf.filename for rf in result] == list(expected)
    for rf, data in zip(result, expected.values()):
        assert rf.checksums == {MD5: md5(data), SHA256: sha256(data)}
        assert rf.size == len(data)
        assert rf.archive_name == LABEL
        assert rf.downloadurl == url(f"pool/main/f/foo/{rf.filename}")
    # only the .dsc file is retrieved during resolution
    assert adapter.urls[-1] == url(f"pool/main/f/foo/foo_{version}.dsc")


def test_source_epoch(make_resolver, adapter):
    repo = Repo()
    repo.add_source(version="2:1.0-1")
    repo.publish(adapter)
    result = make_resolver().resolve(source(version="2:1.0-1"))
    assert result[0].filename == "foo_1.0-1.dsc"
    with pytest.raises(MirrorNotFoundError):
        make_resolver().resolve(source(version="1.0-1"))


SIGNED_A = make_dsc(signature="signature A")
SIGNED_B = make_dsc(signature="signature B")


@pytest.mark.parametrize(
    "checksums,found,fetched",
    [
        ({SHA256: sha256(SIGNED_A)}, True, True),
        ({MD5: md5(SIGNED_A), SHA256: sha256(SIGNED_A)}, True, True),
        # not fetched, as the metadata does not match
        ({SHA256: sha256(SIGNED_B)}, False, False),
        ({MD5: md5(SIGNED_A), SHA256: sha256(SIGNED_B)}, False, False),
        # no common checksum: the fetched .dsc file is verified
        ({SHA512: sha512(SIGNED_A)}, True, True),
        ({SHA512: sha512(SIGNED_B)}, False, True),
        ({SHA1: sha1(SIGNED_A)}, True, True),
    ],
)
def test_source_dsc_checksums(make_resolver, adapter, checksums, found, fetched):
    repo = Repo()
    repo.add_source(dsc=SIGNED_A)
    repo.publish(adapter)
    resolver = make_resolver()
    if found:
        assert len(resolver.resolve(source(checksums=checksums))) == 3
    else:
        with pytest.raises(MirrorNotFoundError, match="ignored 1 with a different checksum"):
            resolver.resolve(source(checksums=checksums))
    assert (url("pool/main/f/foo/foo_1.0-1.dsc") in adapter.urls) == fetched


def test_source_candidates(make_resolver, adapter, caplog):
    """
    The .dsc file identifies a source package. Differently signed .dsc files with the
    same content are different packages.
    """
    repo = Repo()
    repo.add_source(dsc=SIGNED_B)
    repo.add_source(
        dsc=SIGNED_A,
        index="dists/trixie-security/main/source/Sources",
        directory="pool/updates/main/f/foo",
    )
    repo.publish(adapter)
    resolver = make_resolver(suites=["trixie", "trixie-security"])
    result = resolver.resolve(source(checksums={SHA256: sha256(SIGNED_A)}))
    assert result[0].downloadurl == url("pool/updates/main/f/foo/foo_1.0-1.dsc")
    assert result[0].checksums[SHA256] == sha256(SIGNED_A)
    # without checksum, the first package is used
    with caplog.at_level(logging.INFO, logger="debsbom.download.mirror"):
        result = resolver.resolve(source())
    assert result[0].downloadurl == url("pool/main/f/foo/foo_1.0-1.dsc")
    assert "Lookup will be imprecise" in caplog.text
    with pytest.raises(MirrorNotFoundError, match="ignored 2"):
        resolver.resolve(source(checksums={SHA256: sha256(make_dsc())}))


def _replace_line(data: bytes, old: str, new: str) -> bytes:
    assert old.encode() in data
    return data.replace(old.encode(), new.encode())


@pytest.mark.parametrize(
    "dsc,match",
    [
        (make_dsc(source="bar"), "describes source bar 1.0-1"),
        (make_dsc(version="1.0-2"), "describes source foo 1.0-2"),
        (
            make_dsc(files={"foo_1.0.orig.tar.gz": ORIG}),
            r"lists the files \['foo_1.0.orig.tar.gz'\], but",
        ),
        (
            make_dsc(files={**default_files("foo", "1.0-1"), "extra.tar.gz": b"extra"}),
            "lists the files",
        ),
        (
            make_dsc(files={**default_files("foo", "1.0-1"), "foo_1.0.orig.tar.gz": b"other"}),
            "lists 'foo_1.0.orig.tar.gz' with 5 bytes",
        ),
        (
            make_dsc(
                files={**default_files("foo", "1.0-1"), "foo_1.0.orig.tar.gz": b"upstream_sources"}
            ),
            "does not match .* for 'foo_1.0.orig.tar.gz': sha256 is",
        ),
        (make_dsc(lists=("Checksums-Sha1",)), "have no checksum of .* in common"),
        (make_dsc() + b"\xff", "is not valid UTF-8"),
    ],
)
def test_source_dsc_integrity(make_resolver, adapter, dsc, match):
    """A .dsc file which contradicts the Sources index is an error, not a miss."""
    repo = Repo()
    repo.add_source(dsc=dsc)
    repo.publish(adapter)
    with pytest.raises(MirrorIntegrityError, match=match) as e:
        make_resolver().resolve(source(checksums={SHA256: sha256(dsc)}))
    assert not isinstance(e.value, NotFoundError)


@pytest.mark.parametrize(
    "served,status,error,match",
    [
        (
            make_dsc().replace("Jörg".encode(), "Jürg".encode()),
            200,
            MirrorIntegrityError,
            "sha256 is",
        ),
        (make_dsc() + b"\n", 200, MirrorIntegrityError, "is larger than the"),
        (make_dsc()[:-1], 200, MirrorIntegrityError, "size is"),
        (b"", 404, MirrorResolveError, "but not available"),
        (b"", 503, MirrorResolveError, "503"),
    ],
)
def test_source_dsc_retrieval(make_resolver, adapter, served, status, error, match):
    """The retrieved .dsc file must match the metadata, there is no fallback to others."""
    repo = Repo()
    dsc = repo.add_source()
    repo.add_source(index="dists/trixie/contrib/source/Sources", directory="pool/contrib/f/foo")
    repo.publish(adapter)
    adapter.add(url("pool/main/f/foo/foo_1.0-1.dsc"), served, status=status)
    resolver = make_resolver(components=["main", "contrib"])
    for checksums in (None, {SHA256: sha256(dsc)}):
        with pytest.raises(error, match=match) as e:
            resolver.resolve(source(checksums=checksums))
        assert not isinstance(e.value, NotFoundError)
    assert url("pool/contrib/f/foo/foo_1.0-1.dsc") not in adapter.urls


def test_source_dsc_size_limit(make_resolver, adapter, monkeypatch):
    repo = Repo()
    dsc = repo.add_source()
    repo.publish(adapter)
    monkeypatch.setattr(mirror, "MAX_DSC_SIZE", len(dsc) - 1)
    with pytest.raises(MirrorResolveError, match="exceeds the size limit"):
        make_resolver().resolve(source())
    assert url("pool/main/f/foo/foo_1.0-1.dsc") not in adapter.urls
    monkeypatch.setattr(mirror, "MAX_DSC_SIZE", len(dsc))
    assert len(make_resolver().resolve(source())) == 3


def test_source_malformed_dsc(make_resolver, adapter):
    repo = Repo()
    dsc = _replace_line(make_dsc(), f" {md5(ORIG)} {len(ORIG)}", f" {md5(ORIG)} -1")
    repo.add_source(dsc=dsc)
    repo.publish(adapter)
    with pytest.raises(MirrorResolveError, match="invalid size") as e:
        make_resolver().resolve(source())
    assert not isinstance(e.value, NotFoundError)


@pytest.mark.parametrize(
    "body,status,match",
    [
        (b"", 401, "401"),
        (b"", 403, "403"),
        (b"", 429, "429"),
        (b"", 500, "500"),
        (requests.exceptions.ConnectTimeout("timeout"), 200, "timeout"),
        (requests.exceptions.ConnectionError("refused"), 200, "refused"),
        (b"this is not xz data", 200, "is not valid xz data"),
    ],
)
def test_repository_errors(make_resolver, adapter, body, status, match):
    """Problems of the repository are errors, not misses."""
    repo = Repo()
    repo.add_source()
    repo.add_binary()
    repo.publish(adapter)
    adapter.add(url(f"{SOURCES}.xz"), body, status=status)
    adapter.add(url("dists/trixie/main/binary-amd64/Packages.xz"), body, status=status)
    resolver = make_resolver()
    for p in (source(), binary()):
        with pytest.raises(MirrorResolveError, match=match) as e:
            resolver.resolve(p)
        assert not isinstance(e.value, NotFoundError)


def test_unsafe_filename(make_resolver, adapter):
    repo = Repo()
    repo.add_binary(filename="../../etc/foo_1.0-1_amd64.deb")
    repo.publish(adapter)
    with pytest.raises(MirrorResolveError, match="unsafe path") as e:
        make_resolver().resolve(binary())
    assert not isinstance(e.value, NotFoundError)


def test_index_memoization(make_resolver, adapter):
    repo = Repo()
    for name in ("foo", "bar", "baz"):
        repo.add_source(name)
        repo.add_binary(name)
    repo.publish(adapter)
    resolver = make_resolver()
    for name in ("foo", "bar", "baz", "missing"):
        for p in (source(name), binary(name)):
            try:
                resolver.resolve(p)
            except MirrorNotFoundError:
                assert name == "missing"
    indexes = [u for u in adapter.urls if "/dists/" in u]
    assert indexes == [
        url(f"{SOURCES}.xz"),
        url("dists/trixie/main/binary-amd64/Packages.xz"),
    ]
    # a failure is memoized as well
    adapter.add(url("dists/trixie/main/binary-arm64/Packages.xz"), b"", status=500)
    for name in ("foo", "bar"):
        with pytest.raises(MirrorResolveError, match="500"):
            resolver.resolve(binary(name, arch="arm64"))
    assert adapter.urls.count(url("dists/trixie/main/binary-arm64/Packages.xz")) == 1


@pytest.mark.parametrize("path", ["./", "sub/dir/"])
def test_flat_repository(make_resolver, adapter, path):
    prefix = path.removeprefix("./")
    repo = Repo()
    dsc = repo.add_source(index=f"{prefix}Sources", directory=prefix.rstrip("/") or ".")
    repo.add_binary(index=f"{prefix}Packages", filename=f"{prefix}foo_1.0-1_amd64.deb")
    repo.publish(adapter)
    resolver = make_resolver(suites=[path], components=[])
    result = resolver.resolve(source(checksums={SHA256: sha256(dsc)}))
    assert [rf.downloadurl for rf in result] == [
        url(f"{prefix}foo_1.0-1.dsc"),
        url(f"{prefix}foo_1.0.orig.tar.gz"),
        url(f"{prefix}foo_1.0-1.debian.tar.xz"),
    ]
    (rf,) = resolver.resolve(binary())
    assert rf.downloadurl == url(f"{prefix}foo_1.0-1_amd64.deb")


def test_download_from_mirror(make_resolver, fake_http, tmp_path):
    """Resolved files are downloaded and verified, a source package is kept together."""
    session, adapter = fake_http
    repo = Repo()
    dsc = repo.add_source()
    data = repo.add_binary()
    repo.add_binary("bar", data=b"bar")
    repo.publish(adapter)
    # a different file than in the metadata
    adapter.add(url("pool/main/b/bar/bar_1.0-1_amd64.deb"), b"BAR")
    resolver = make_resolver()
    src = source(checksums={SHA256: sha256(dsc)})
    # no common checksum with the metadata: verified independently
    foo = binary(checksums={SHA512: sha512(data)})
    bar = binary("bar")
    downloader = PackageDownloader(tmp_path, session=session)
    for p in (src, foo, bar):
        downloader.register(resolver.resolve(p), p)
    results = list(downloader.download())
    assert [r.status for r in results] == [DownloadStatus.OK] * 4 + [
        DownloadStatus.CHECKSUM_MISMATCH
    ]
    assert all(r.source.startswith(f"{ROOT}/pool/") for r in results)
    dsc_path = SourceArchiveMerger.locate_artifact(src, tmp_path / "sources")
    assert dsc_path == tmp_path / "sources" / LABEL / "foo_1.0-1.dsc"
    for name in default_files("foo", "1.0-1"):
        assert (dsc_path.parent / name).read_bytes() in (ORIG, DEBIAN)
    assert (tmp_path / "binaries" / LABEL / "foo_1.0-1_amd64.deb").read_bytes() == data
    assert not (tmp_path / "binaries" / LABEL / "bar_1.0-1_amd64.deb").exists()

    downloader.register(resolver.resolve(foo), binary(checksums={SHA512: sha512(b"other")}))
    (result,) = downloader.download()
    assert result.status == DownloadStatus.CHECKSUM_MISMATCH


# command line


@pytest.fixture
def cli(fake_http, monkeypatch, capsys, tmp_path):
    """Run the download command with the fake session, return the JSON results."""
    session, _ = fake_http
    monkeypatch.setattr(
        download_cmd.DownloadInput, "_create_default_session", staticmethod(lambda: session)
    )

    def run(*argv, stdin=b""):
        monkeypatch.setattr(sys, "stdin", io.BufferedReader(io.BytesIO(stdin)))
        args = setup_parser().parse_args(
            ["--json", "download", "--outdir", str(tmp_path / "downloads"), *argv]
        )
        download_cmd.DownloadCmd.run(args)
        results = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        for r in results:
            jsonschema.validate(r, schema=schema.download)
        return results

    return run


MIRROR_ARGS = ["--resolver", "debian-mirror", "--mirror-url", ROOT, "--mirror-suite", "trixie"]
FALLBACK_ARGS = [*MIRROR_ARGS, "--mirror-component", "main", "--snapshot-fallback"]
SNAPSHOT = "https://snapshot.debian.org"


def serve_snapshot(adapter, name, version, files, arch="amd64"):
    """Serve the files of a package with the snapshot API, the arch 'source' for sources."""
    result, fileinfo = [], {}
    for filename, data in files.items():
        digest = sha1(data)
        result.append({"hash": digest, "architecture": arch})
        fileinfo[digest] = [
            {
                "name": filename,
                "archive_name": "debian",
                "path": f"/pool/main/{name[0]}/{name}",
                "first_seen": "20250101T000000Z",
                "size": len(data),
            }
        ]
        adapter.add(f"{SNAPSHOT}/file/{digest}/{filename}", data)
    if arch == "source":
        api = f"/mr/package/{name}/{version}/srcfiles?fileinfo=1"
    else:
        api = f"/mr/binary/{name}/{version}/binfiles?fileinfo=1"
    adapter.add(SNAPSHOT + api, json.dumps({"result": result, "fileinfo": fileinfo}).encode())


def snapshot_requests(adapter) -> list[str]:
    return [u for u in adapter.urls if u.startswith(SNAPSHOT)]


def test_cli_defaults():
    args = setup_parser().parse_args(["download"])
    assert args.resolver == "debian-snapshot"
    for option in download_cmd.MIRROR_OPTIONS:
        assert getattr(args, option) is None


def test_cli_ordered_options(fake_http, tmp_path):
    session, adapter = fake_http
    args = setup_parser().parse_args(
        ["download", *MIRROR_ARGS, "--mirror-suite", "trixie-updates"]
        + ["--mirror-component", "main", "--mirror-component", "contrib"]
        + ["--mirror-architecture", "arm64", "--mirror-architecture", "amd64"]
    )
    assert args.mirror_suite == ["trixie", "trixie-updates"]
    resolver = download_cmd.DownloadCmd._create_default_resolver(args, session, tmp_path)
    assert isinstance(resolver, MirrorResolver)
    assert resolver.repository.suites == ("trixie", "trixie-updates")
    assert resolver.repository.components == ("main", "contrib")
    assert resolver.repository.architectures == ("arm64", "amd64")
    # not cached across runs
    assert type(resolver.cache) is PackageResolverCache
    assert not (tmp_path / ".cache").exists()
    assert adapter.requests == []


@pytest.mark.parametrize(
    "argv,match",
    [
        (["--mirror-url", ROOT], "--mirror-url requires the built-in 'debian-mirror' resolver"),
        (["--mirror-suite", "trixie"], "--mirror-suite requires the built-in"),
        (["--mirror-architecture", "amd64"], "--mirror-architecture requires the built-in"),
        (["--resolver", "debian-mirror"], "requires --mirror-url"),
        (["--resolver", "debian-mirror", "--mirror-url", ROOT], "at least one --mirror-suite"),
        (MIRROR_ARGS, "at least one component is required"),
        (MIRROR_ARGS + ["--mirror-suite", "./", "--mirror-component", "main"], "combined"),
        (
            ["--resolver", "debian-mirror", "--mirror-url", ROOT, "--mirror-suite", "./"]
            + ["--mirror-component", "main"],
            "have no components",
        ),
        (
            MIRROR_ARGS + ["--mirror-component", "main", "--mirror-architecture", "$(ARCH)"],
            "substitution",
        ),
        (
            MIRROR_ARGS + ["--mirror-component", "main", "--mirror-architecture", "any"],
            "wildcard",
        ),
        (
            ["--resolver", "debian-mirror", "--mirror-url", "https://user:pw@example.org/debian"]
            + ["--mirror-suite", "trixie", "--mirror-component", "main"],
            "credentials",
        ),
        (
            ["--resolver", "debian-mirror", "--mirror-url", "ftp://example.org/debian"]
            + ["--mirror-suite", "trixie", "--mirror-component", "main"],
            "must use http, https or file",
        ),
        (
            ["--resolver", "debian-mirror", "--mirror-url", f"{ROOT}?token=secret"]
            + ["--mirror-suite", "trixie", "--mirror-component", "main"],
            "query or fragment",
        ),
        (["--snapshot-fallback"], "--snapshot-fallback requires the built-in"),
        (["--no-snapshot-fallback"], "--no-snapshot-fallback requires the built-in"),
        (["--resolver", "debian-mirror", "--snapshot-fallback"], "requires --mirror-url"),
        # the repository is validated before the fallback is set up
        (MIRROR_ARGS + ["--snapshot-fallback"], "at least one component is required"),
    ],
)
def test_cli_invalid(cli, adapter, tmp_path, argv, match):
    """The options are validated before any input is read or request is made."""
    with pytest.raises(ValueError, match=match):
        cli(*argv, stdin=b"foo 1.0-1 amd64\n")
    assert adapter.requests == []
    assert sys.stdin.read() == b"foo 1.0-1 amd64\n"
    outdir = tmp_path / "downloads"
    assert not outdir.exists() or not any(outdir.iterdir())


def test_cli_plugin_replaces_mirror(cli, monkeypatch, adapter):
    """A plugin using the same name is called like any plugin and cannot be configured."""
    calls = []

    class _Resolver(Resolver):
        def resolve(self, p):
            raise NotFoundError("not found")

    def setup_resolver(*args, **kwargs):
        calls.append((args, kwargs))
        return _Resolver()

    monkeypatch.setitem(download_cmd.RESOLVERS, "debian-mirror", setup_resolver)
    with pytest.raises(ValueError, match="requires the built-in"):
        cli(*MIRROR_ARGS, stdin=b"foo 1.0-1 amd64\n")
    with pytest.raises(ValueError, match="--snapshot-fallback requires the built-in"):
        cli("--resolver", "debian-mirror", "--snapshot-fallback", stdin=b"foo 1.0-1 amd64\n")
    (result,) = cli("--resolver", "debian-mirror", stdin=b"foo 1.0-1 amd64\n")
    assert result["status"] == "not_found"
    ((args, kwargs),) = calls
    assert len(args) == 1 and isinstance(args[0], requests.Session) and kwargs == {}


def test_cli_package_list(cli, adapter, tmp_path):
    """Packages are resolved in a local repository and downloaded, unknown ones reported."""
    repo = Repo()
    dsc = repo.add_source(version="2:1.0-1")
    data = repo.add_binary(version="2:1.0-1")
    root = repo.write(tmp_path / "repo")
    stdin = b"foo 2:1.0-1 amd64\nfoo 2:1.0-1 source\nbar 1.0-1 amd64\n"
    results = cli(
        "--resolver",
        "debian-mirror",
        "--mirror-url",
        root,
        "--mirror-suite",
        "trixie",
        "--mirror-component",
        "main",
        stdin=stdin,
    )
    assert adapter.requests == []
    label = archive_label(root)
    by_file = {r.get("filename", r["package"]["name"]): r for r in results}
    assert by_file["bar"]["status"] == "not_found"
    assert by_file["bar"]["source"] == ""
    expected = {
        "foo_1.0-1_amd64.deb": ("binaries", data),
        "foo_1.0-1.dsc": ("sources", dsc),
        "foo_1.0.orig.tar.gz": ("sources", ORIG),
        "foo_1.0-1.debian.tar.xz": ("sources", DEBIAN),
    }
    for filename, (kind, content) in expected.items():
        r = by_file[filename]
        assert r["status"] == "ok"
        assert r["source"].startswith(f"{root}/pool/main/f/foo/")
        path = tmp_path / "downloads" / kind / label / filename
        assert Path(r["path"]) == path.resolve()
        assert path.read_bytes() == content
    assert len(results) == 5
    # nothing is cached across runs
    assert not (tmp_path / "downloads" / ".cache").exists()


def test_cli_sbom(cli, tmp_path):
    """Packages of an SBOM are resolved with their checksums."""
    pytest.importorskip("cyclonedx")
    repo = Repo()
    dsc = repo.add_source("dash", "0.5.12-12")
    deb = repo.add_binary("dash", "0.5.12-12")
    repo.add_binary("libxtst6", "2:1.2.3-1.1")
    # same identity, but a different checksum than in the SBOM
    repo.add_binary("base-files", "13.8+deb13u3")
    root = repo.write(tmp_path / "repo")

    sbom = json.loads(Path("tests/data/filter.cdx.json").read_text())
    for c in sbom["components"]:
        if c["name"] == "dash":
            data = dsc if c["purl"].endswith("arch=source") else deb
            c["hashes"] = [
                {"alg": "MD5", "content": md5(data)},
                {"alg": "SHA-256", "content": sha256(data)},
            ]
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_path.write_text(json.dumps(sbom))

    results = cli(
        str(sbom_path),
        "--resolver",
        "debian-mirror",
        "--mirror-url",
        root,
        "--mirror-suite",
        "trixie",
        "--mirror-component",
        "main",
    )
    ok = sorted(r["filename"] for r in results if r["status"] == "ok")
    assert ok == [
        "dash_0.5.12-12.debian.tar.xz",
        "dash_0.5.12-12.dsc",
        "dash_0.5.12-12_amd64.deb",
        "dash_0.5.12.orig.tar.gz",
        "libxtst6_1.2.3-1.1_amd64.deb",
    ]
    not_found = sorted(r["package"]["purl"] for r in results if r["status"] == "not_found")
    assert not_found == [
        "pkg:deb/debian/accountsservice@23.13.9-7?arch=amd64",
        "pkg:deb/debian/accountsservice@23.13.9-7?arch=source",
        "pkg:deb/debian/base-files@13.8%2Bdeb13u3?arch=amd64",
        "pkg:deb/debian/base-files@13.8%2Bdeb13u3?arch=source",
        "pkg:deb/debian/x11vnc@0.9.16-9?arch=amd64",
    ]


@pytest.mark.parametrize("fallback", [[], ["--snapshot-fallback"]])
def test_cli_skipped_packages_are_not_looked_up(cli, adapter, fallback):
    repo = Repo()
    repo.add_binary()
    repo.publish(adapter)
    args = [*MIRROR_ARGS, "--mirror-component", "main", *fallback]
    stdin = b"foo 1.0-1 amd64\nbar 1.0-1 amd64\n"
    results = cli(*args, "--skip-pkgs", "foo 1.0-1 amd64\nbar 1.0-1 amd64", stdin=stdin)
    assert results == []
    assert adapter.requests == []
    (result,) = cli(*args, "--skip-pkgs", "bar 1.0-1 amd64", stdin=stdin)
    assert result["status"] == "ok"
    assert snapshot_requests(adapter) == []
    # only a package the repository does not have is looked up on snapshot
    results = cli(*args, stdin=stdin)
    assert [r["status"] for r in results] == ["not_found", "ok"]
    assert snapshot_requests(adapter) == (
        [f"{SNAPSHOT}/mr/binary/bar/1.0-1/binfiles?fileinfo=1"] if fallback else []
    )


def test_cli_resolution_error(cli, adapter, caplog):
    """Repository problems are reported per package, like unresolved packages."""
    adapter.add(url("dists/trixie/main/binary-amd64/Packages.xz"), b"", status=401)
    with caplog.at_level(logging.WARNING):
        (result,) = cli(*MIRROR_ARGS, "--mirror-component", "main", stdin=b"foo 1.0-1 amd64\n")
    assert result["status"] == "not_found"
    assert result["source"] == ""
    assert "failed to resolve binary package: foo@1.0-1: cannot retrieve" in caplog.text
    assert "401" in caplog.text


# snapshot fallback


@pytest.mark.parametrize(
    "option,fallback",
    [
        ([], None),
        (["--snapshot-fallback"], True),
        (["--no-snapshot-fallback"], False),
        (["--snapshot-fallback", "--no-snapshot-fallback"], False),
    ],
)
def test_cli_snapshot_fallback_option(fake_http, tmp_path, option, fallback):
    session, adapter = fake_http
    args = setup_parser().parse_args(
        ["download", *MIRROR_ARGS, "--mirror-component", "main", *option]
    )
    assert args.snapshot_fallback is fallback
    resolver = download_cmd.DownloadCmd._create_default_resolver(args, session, tmp_path)
    if fallback:
        assert isinstance(resolver, FallbackResolver)
        assert isinstance(resolver.primary, MirrorResolver)
        assert isinstance(resolver.fallback, UpstreamResolver)
        assert resolver.fallback.sdl.rs is session
        # only the snapshot resolver is cached, like the debian-snapshot resolver
        assert type(resolver.cache) is PackageResolverCache
        assert type(resolver.primary.cache) is PackageResolverCache
        assert isinstance(resolver.fallback.cache, PersistentResolverCache)
        assert resolver.fallback.cache.cachedir == tmp_path / ".cache" / "debian-snapshot"
    else:
        assert isinstance(resolver, MirrorResolver)
        assert not (tmp_path / ".cache").exists()
    assert adapter.requests == []


def test_cli_snapshot_fallback_replaced_snapshot(fake_http, tmp_path, monkeypatch):
    """The fallback uses the built-in snapshot resolver, without the cache of a replacement."""
    session, adapter = fake_http
    calls = []
    monkeypatch.setitem(download_cmd.RESOLVERS, "debian-snapshot", calls.append)
    args = setup_parser().parse_args(["download", *FALLBACK_ARGS])
    resolver = download_cmd.DownloadCmd._create_default_resolver(args, session, tmp_path)
    assert calls == []
    assert isinstance(resolver.fallback, UpstreamResolver)
    assert type(resolver.fallback.cache) is PackageResolverCache
    assert not (tmp_path / ".cache").exists()


@pytest.mark.parametrize("option", [[], ["--no-snapshot-fallback"]])
def test_cli_snapshot_fallback_disabled(cli, adapter, tmp_path, option):
    """By default, packages are not looked up on snapshot."""
    repo = Repo()
    repo.add_binary()
    repo.publish(adapter)
    serve_snapshot(adapter, "bar", "1.0-1", {"bar_1.0-1_amd64.deb": b"bar"})
    args = [*MIRROR_ARGS, "--mirror-component", "main", *option]
    results = cli(*args, stdin=b"foo 1.0-1 amd64\nbar 1.0-1 amd64\n")
    assert [r["status"] for r in results] == ["not_found", "ok"]
    assert snapshot_requests(adapter) == []
    assert not (tmp_path / "downloads" / ".cache").exists()


def test_cli_snapshot_fallback(cli, adapter, tmp_path):
    """Only packages the repository does not have are looked up on snapshot."""
    repo = Repo()
    foo_dsc = repo.add_source()
    foo_deb = repo.add_binary()
    repo.publish(adapter)
    bar_deb = b"bar 1.0-1 amd64"
    serve_snapshot(adapter, "bar", "1.0-1", {"bar_1.0-1_amd64.deb": bar_deb})
    bar_files = {"bar_1.0.orig.tar.gz": b"bar sources", "bar_1.0-1.debian.tar.xz": b"bar debian"}
    bar_sources = {"bar_1.0-1.dsc": make_dsc("bar", files=bar_files), **bar_files}
    serve_snapshot(adapter, "bar", "1.0-1", bar_sources, arch="source")
    pkgs = ["foo 1.0-1 amd64", "foo 1.0-1 source", "bar 1.0-1 amd64", "bar 1.0-1 source"]
    stdin = "\n".join([*pkgs, "baz 1.0-1 amd64"]).encode()

    results = cli(*FALLBACK_ARGS, stdin=stdin)
    assert [u for u in snapshot_requests(adapter) if "/mr/" in u] == [
        f"{SNAPSHOT}/mr/binary/bar/1.0-1/binfiles?fileinfo=1",
        f"{SNAPSHOT}/mr/package/bar/1.0-1/srcfiles?fileinfo=1",
        f"{SNAPSHOT}/mr/binary/baz/1.0-1/binfiles?fileinfo=1",
    ]
    by_file = {r.get("filename") or r["package"]["name"]: r for r in results}
    assert by_file.pop("baz")["status"] == "not_found"
    expected = {
        "foo_1.0-1_amd64.deb": ("binaries", LABEL, foo_deb),
        "foo_1.0-1.dsc": ("sources", LABEL, foo_dsc),
        **{n: ("sources", LABEL, d) for n, d in default_files("foo", "1.0-1").items()},
        "bar_1.0-1_amd64.deb": ("binaries", "debian", bar_deb),
        **{n: ("sources", "debian", d) for n, d in bar_sources.items()},
    }
    assert by_file.keys() == expected.keys()
    downloads = tmp_path / "downloads"
    for filename, (kind, archive, data) in expected.items():
        r = by_file[filename]
        assert r["status"] == "ok"
        if archive == LABEL:
            assert r["source"] == url(f"pool/main/f/foo/{filename}")
        else:
            assert r["source"] == f"{SNAPSHOT}/file/{sha1(data)}/{filename}"
        assert (downloads / kind / archive / filename).read_bytes() == data
    # each source package is complete in the directory of its archive
    for p, archive in ((source("foo"), LABEL), (source("bar"), "debian")):
        dsc = SourceArchiveMerger.locate_artifact(p, downloads / "sources")
        assert dsc == downloads / "sources" / archive / p.dscfile()

    # the repository is asked again, snapshot results are cached
    adapter.requests.clear()
    results = cli(*FALLBACK_ARGS, stdin=stdin)
    assert sorted(r["status"] for r in results) == ["not_found"] + ["ok"] * len(expected)
    assert url("dists/trixie/main/binary-amd64/Packages.xz") in adapter.urls
    assert snapshot_requests(adapter) == []


def test_snapshot_fallback_checksum_mismatch(fake_http, tmp_path):
    """A package which differs from the one in the repository is looked up on snapshot."""
    session, adapter = fake_http
    repo = Repo()
    data = repo.add_binary()
    repo.publish(adapter)
    rebuilt = b"rebuilt foo 1.0-1 amd64"
    serve_snapshot(adapter, "foo", "1.0-1", {"foo_1.0-1_amd64.deb": rebuilt})
    args = setup_parser().parse_args(["download", *FALLBACK_ARGS])
    resolver = download_cmd.DownloadCmd._create_default_resolver(args, session, tmp_path)

    (rf,) = resolver._resolve_pkg(binary(checksums={SHA256: sha256(data)}))
    assert rf.downloadurl == url("pool/main/f/foo/foo_1.0-1_amd64.deb")
    assert snapshot_requests(adapter) == []
    (rf,) = resolver._resolve_pkg(binary(checksums={SHA256: sha256(rebuilt)}))
    assert rf.downloadurl == f"{SNAPSHOT}/file/{sha1(rebuilt)}/foo_1.0-1_amd64.deb"
    assert snapshot_requests(adapter) == [f"{SNAPSHOT}/mr/binary/foo/1.0-1/binfiles?fileinfo=1"]


@pytest.mark.parametrize(
    "pkg,path,body,status,reason",
    [
        # operational errors
        ("foo 1.0-1 amd64", "binary-amd64/Packages.xz", b"", 401, "401"),
        ("foo 1.0-1 amd64", "binary-amd64/Packages.xz", b"", 503, "503"),
        (
            "foo 1.0-1 amd64",
            "binary-amd64/Packages.xz",
            requests.ConnectTimeout("timed out"),
            200,
            "timed out",
        ),
        # metadata errors
        ("foo 1.0-1 amd64", "binary-amd64/Packages.xz", b"this is not xz data", 200, "xz"),
        ("foo 1.0-1 all", None, None, None, "configure the architectures"),
        # integrity errors
        ("foo 1.0-1 source", "foo_1.0-1.dsc", b"tampered", 200, "does not match"),
        ("foo 1.0-1 source", "foo_1.0-1.dsc", b"", 404, "is listed in the metadata"),
    ],
)
def test_cli_snapshot_fallback_errors(cli, adapter, caplog, pkg, path, body, status, reason):
    """Repository errors are reported, they are no reason to look up a package on snapshot."""
    repo = Repo()
    repo.add_source()
    repo.add_binary()
    repo.publish(adapter)
    if path:
        directory = "pool/main/f/foo" if path.endswith(".dsc") else "dists/trixie/main"
        adapter.add(url(f"{directory}/{path}"), body, status=status)
    with caplog.at_level(logging.WARNING):
        (result,) = cli(*FALLBACK_ARGS, stdin=f"{pkg}\n".encode())
    assert result["status"] == "not_found"
    assert reason in caplog.text
    assert snapshot_requests(adapter) == []


def test_cli_snapshot_fallback_download_failure(cli, adapter):
    """
    The fallback applies to resolving: a file the repository lists, but fails to provide,
    is not downloaded from snapshot instead.
    """
    repo = Repo()
    data = repo.add_binary()
    repo.publish(adapter)
    deb = url("pool/main/f/foo/foo_1.0-1_amd64.deb")
    adapter.add(deb, b"", status=404)
    serve_snapshot(adapter, "foo", "1.0-1", {"foo_1.0-1_amd64.deb": data})
    with pytest.raises(requests.HTTPError, match="404"):
        cli(*FALLBACK_ARGS, stdin=b"foo 1.0-1 amd64\n")
    assert adapter.urls[-1] == deb
    assert snapshot_requests(adapter) == []
