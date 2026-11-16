# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

import gzip
import hashlib
import lzma

import pytest
import requests
import urllib3

from debsbom.apt import remote
from debsbom.apt.remote import (
    RemoteRepository,
    RepositoryAccessError,
    RepositoryConfigurationError,
    RepositoryError,
    RepositoryMetadataError,
)
from debsbom.util.checksum import ChecksumAlgo

ROOT = "https://mirror.example.org/debian"
DEB = b"binary package"
DSC = b"source control file"
TARBALL = b"upstream sources"
SOURCES = f"{ROOT}/dists/trixie/main/source/Sources"
PACKAGES = f"{ROOT}/dists/trixie/main/binary-amd64/Packages"


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


LISTS = {"Files": md5, "Checksums-Sha1": sha1, "Checksums-Sha256": sha256}


def binary_paragraph(
    name="foo", version="1.0-1", arch="amd64", filename=None, data=DEB, checksums=True
):
    if filename is None:
        filename = f"pool/main/f/{name}/{name}_{version.split(':')[-1]}_{arch}.deb"
    lines = [
        f"Package: {name}",
        f"Version: {version}",
        f"Architecture: {arch}",
        "Maintainer: Jörg Müller <jm@example.org>",
        f"Filename: {filename}",
        f"Size: {len(data)}",
    ]
    if checksums:
        lines += [f"MD5sum: {md5(data)}", f"SHA256: {sha256(data)}"]
    lines.append("Description: test package ✓")
    return "\n".join(lines) + "\n"


def source_paragraph(
    name="foo", version="1.0-1", directory="pool/main/f/foo", files=None, fields=None
):
    if files is None:
        files = {f"{name}_{version}.dsc": DSC, f"{name}_1.0.orig.tar.gz": TARBALL}
    lines = [
        f"Package: {name}",
        f"Version: {version}",
        "Maintainer: Jörg Müller <jm@example.org>",
        f"Directory: {directory}",
    ]
    for field in fields or ("Files", "Checksums-Sha256"):
        lines.append(f"{field}:")
        lines += [f" {LISTS[field](d)} {len(d)} {n}" for n, d in files.items()]
    return "\n".join(lines) + "\n"


def index(*paragraphs: str) -> bytes:
    return "\n".join(paragraphs).encode()


def xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ)


def serve(adapter, url, data, variant=".xz"):
    compress = {".xz": xz, ".gz": gzip.compress, "": lambda d: d}[variant]
    adapter.add(url + variant, compress(data))


@pytest.fixture
def mirror(fake_http):
    session, adapter = fake_http

    def make(suites=("trixie",), components=("main",), architectures=(), url=ROOT):
        return RemoteRepository(session, url, suites, components, architectures)

    return make, adapter


@pytest.mark.parametrize(
    "url,suites,components,expected_url",
    [
        ("https://mirror.example.org/debian/", ["trixie"], ["main"], ROOT),
        ("HTTP://Mirror.Example.org:8080/debian", ["trixie"], ["main"], None),
        ("http://[::1]:8080/", ["stretch/updates"], ["main"], "http://[::1]:8080"),
        ("file://localhost/srv/repo", ["./"], [], "file:///srv/repo"),
        ("file://LOCALHOST/srv/repo", ["./", "/"], [], "file:///srv/repo"),
        ("file:/srv/repo/", ["/"], [], "file:///srv/repo"),
        ("file:///", ["sub/dir/", "./other/"], [], "file://"),
    ],
)
def test_valid_configuration(fake_http, url, suites, components, expected_url):
    session, adapter = fake_http
    repo = RemoteRepository(session, url, suites, components)
    if expected_url:
        assert repo.url == expected_url
    else:
        assert repo.url == "http://mirror.example.org:8080/debian"
    # the configuration is validated without any request
    assert adapter.requests == []


@pytest.mark.parametrize(
    "url,suites,components,architectures,match",
    [
        (ROOT, [], ["main"], [], "at least one suite"),
        (ROOT, ["trixie", "./"], ["main"], [], "cannot be combined"),
        (ROOT, ["./"], ["main"], [], "have no components"),
        (ROOT, ["trixie"], [], [], "at least one component"),
        (ROOT, ["./"], [], ["amd64"], "architectures cannot be configured"),
        (ROOT, ["../trixie"], ["main"], [], "invalid suite"),
        (ROOT, ["trixie/"], ["main"], [], "have no components"),
        (ROOT, ["../"], [], [], "invalid exact path"),
        (ROOT, ["/abs/"], [], [], "invalid exact path"),
        (ROOT, ["sub/./dir/"], [], [], "invalid exact path"),
        (ROOT, ["$(ARCH)/"], [], [], "substitution variables"),
        (ROOT, ["trixie"], ["main/../x"], [], "invalid component"),
        (ROOT, ["trixie"], ["main"], ["$(ARCH)"], "substitution variables"),
        (ROOT, ["trixie"], ["main"], ["any"], "wildcard"),
        (ROOT, ["trixie"], ["main"], ["linux-any"], "wildcard"),
        (ROOT, ["trixie"], ["main"], ["any-amd64"], "wildcard"),
        (ROOT, ["trixie"], ["main"], ["source"], "invalid architecture"),
        (ROOT, ["trixie"], ["main"], ["AMD64"], "invalid architecture"),
        ("https://user:secret@mirror.example.org/debian", ["trixie"], ["main"], [], "credentials"),
        ("https://token@mirror.example.org/debian", ["trixie"], ["main"], [], "credentials"),
        (ROOT + "?token=x", ["trixie"], ["main"], [], "query or fragment"),
        (ROOT + "#x", ["trixie"], ["main"], [], "query or fragment"),
        ("ftp://mirror.example.org/debian", ["trixie"], ["main"], [], "must use http"),
        ("mirror.example.org/debian", ["trixie"], ["main"], [], "must use http"),
        ("file:repo", ["./"], [], [], "absolute local file URL"),
        ("file://server/repo", ["./"], [], [], "absolute local file URL"),
        ("https:///debian", ["trixie"], ["main"], [], "has no host"),
        ("https://mirror.example.org:x/", ["trixie"], ["main"], [], "invalid repository URL"),
        ("https://mirror.example.org/a b", ["trixie"], ["main"], [], "invalid repository URL"),
        ("https://mirror.example.org/\x01", ["trixie"], ["main"], [], "invalid repository URL"),
        ("https://mirror.example.org\\debian", ["trixie"], ["main"], [], "invalid repository"),
        ("https://mirror.example.org/../debian", ["trixie"], ["main"], [], "dot segments"),
    ],
)
def test_invalid_configuration(fake_http, url, suites, components, architectures, match):
    session, adapter = fake_http
    with pytest.raises(ValueError, match=match):
        RemoteRepository(session, url, suites, components, architectures)
    assert adapter.requests == []


@pytest.mark.parametrize("variant", [".xz", ".gz", ""])
def test_index_variants(mirror, variant):
    make, adapter = mirror
    serve(adapter, PACKAGES, index(binary_paragraph()), variant)
    serve(adapter, SOURCES, index(source_paragraph()), variant)
    repo = make()

    record = next(repo.find_binaries("foo", "1.0-1", "amd64"))
    assert record.file.path == "pool/main/f/foo/foo_1.0-1_amd64.deb"
    assert record.file.size == len(DEB)
    assert record.file.checksums == {
        ChecksumAlgo.MD5SUM: md5(DEB),
        ChecksumAlgo.SHA256SUM: sha256(DEB),
    }
    assert record.index == PACKAGES
    source = next(repo.find_sources("foo", "1.0-1"))
    assert [f.path for f in source.files] == [
        "pool/main/f/foo/foo_1.0-1.dsc",
        "pool/main/f/foo/foo_1.0.orig.tar.gz",
    ]
    assert source.dsc.name == "foo_1.0-1.dsc"

    variants = [".xz", ".gz", ""]
    expected = variants[: variants.index(variant) + 1]
    assert adapter.urls == [PACKAGES + v for v in expected] + [SOURCES + v for v in expected]
    assert all(kw["timeout"] == remote.METADATA_TIMEOUT for kw in adapter.kwargs)
    assert all(r.headers["Accept-Encoding"] == "identity" for r in adapter.requests)


def test_concatenated_streams(mirror):
    make, adapter = mirror
    first, second = binary_paragraph(), binary_paragraph(name="bar")
    adapter.add(PACKAGES + ".xz", xz(first.encode() + b"\n") + xz(second.encode()) + b"\0" * 4)
    adapter.add(
        PACKAGES.replace("trixie", "sid") + ".gz",
        gzip.compress(first.encode() + b"\n") + gzip.compress(second.encode()),
    )
    repo = make(suites=["trixie", "sid"])
    assert [r.index for r in repo.find_binaries("bar", "1.0-1", "amd64")] == [
        PACKAGES,
        PACKAGES.replace("trixie", "sid"),
    ]


@pytest.mark.parametrize(
    "variant,data,match",
    [
        (".xz", b"this is not xz compressed data", "not valid xz data"),
        (".xz", b"not xz", "truncated"),
        (".xz", xz(index(binary_paragraph()))[:-20], "truncated|not valid xz"),
        (".xz", xz(index(binary_paragraph())) + b"garbage, not a stream", "not valid xz data"),
        (".gz", b"not gzip data", "not valid gzip data"),
        (".gz", gzip.compress(index(binary_paragraph()))[:-10], "truncated"),
        ("", b"Package: foo\nMaintainer: \xff\n", "not valid UTF-8"),
        (".xz", xz(b"Package: foo\nVersion: 1.0-1\n"), "without valid Package, Version"),
    ],
)
def test_malformed_index(mirror, variant, data, match):
    make, adapter = mirror
    adapter.add(PACKAGES + variant, data)
    if variant:
        # a valid variant with lower preference must not be used instead
        serve(adapter, PACKAGES, index(binary_paragraph()), "")
    repo = make()
    with pytest.raises(RepositoryMetadataError, match=match):
        next(repo.find_binaries("foo", "1.0-1", "amd64"))
    assert adapter.urls[-1] == PACKAGES + variant


def test_size_limits(mirror, monkeypatch):
    make, adapter = mirror
    data = index(binary_paragraph())
    serve(adapter, PACKAGES, data)
    serve(adapter, PACKAGES.replace("trixie", "sid"), data, "")
    serve(adapter, PACKAGES.replace("trixie", "bookworm"), data)
    adapter.add(
        PACKAGES.replace("trixie", "forky") + ".xz", xz(data), headers={"Content-Length": "999"}
    )

    monkeypatch.setattr(remote, "MAX_INDEX_SIZE", len(data) - 1)
    with pytest.raises(RepositoryMetadataError, match="after decompression"):
        next(make().find_binaries("foo", "1.0-1", "amd64"))
    with pytest.raises(RepositoryMetadataError, match="size limit"):
        next(make(suites=["sid"]).find_binaries("foo", "1.0-1", "amd64"))

    monkeypatch.setattr(remote, "MAX_INDEX_SIZE", len(data))
    assert next(make().find_binaries("foo", "1.0-1", "amd64"))
    assert next(make(suites=["sid"]).find_binaries("foo", "1.0-1", "amd64"))

    monkeypatch.setattr(remote, "MAX_COMPRESSED_INDEX_SIZE", len(xz(data)) - 1)
    with pytest.raises(RepositoryMetadataError, match="size limit"):
        next(make(suites=["bookworm"]).find_binaries("foo", "1.0-1", "amd64"))
    monkeypatch.setattr(remote, "MAX_COMPRESSED_INDEX_SIZE", 998)
    with pytest.raises(RepositoryMetadataError, match="size limit"):
        next(make(suites=["forky"]).find_binaries("foo", "1.0-1", "amd64"))


class _BrokenStream:
    def read(self, *args, **kwargs):
        raise urllib3.exceptions.ProtocolError("connection reset")

    def close(self):
        pass


@pytest.mark.parametrize(
    "status,body",
    [
        (401, b""),
        (403, b""),
        (410, b""),
        (429, b""),
        (500, b""),
        (503, b""),
        (200, requests.exceptions.ConnectionError("connection refused")),
        (200, requests.exceptions.ReadTimeout("timed out")),
        (200, _BrokenStream()),
    ],
)
def test_access_errors(mirror, status, body):
    make, adapter = mirror
    adapter.add(PACKAGES + ".xz", body, status=status)
    serve(adapter, PACKAGES, index(binary_paragraph()), ".gz")
    repo = make()
    with pytest.raises(RepositoryAccessError, match="cannot retrieve"):
        next(repo.find_binaries("foo", "1.0-1", "amd64"))
    # the failure is not hidden by another variant
    assert adapter.urls == [PACKAGES + ".xz"]


def test_index_memoization(mirror, monkeypatch):
    make, adapter = mirror
    parsed = []
    parse_index = remote._parse_index

    def counting_parse_index(data, binary, url):
        parsed.append(url)
        return parse_index(data, binary, url)

    monkeypatch.setattr(remote, "_parse_index", counting_parse_index)
    serve(adapter, PACKAGES, index(binary_paragraph(), binary_paragraph(name="bar")))
    adapter.add(SOURCES + ".xz", status=500)
    repo = make(suites=["trixie", "sid"])

    for name in ["foo", "bar", "foo"]:
        assert next(repo.find_binaries(name, "1.0-1", "amd64")).name == name
    # misses search all indexes, including the ones that are not available
    for name in ["baz", "qux"]:
        assert list(repo.find_binaries(name, "1.0-1", "amd64")) == []
    for _ in range(2):
        with pytest.raises(RepositoryAccessError):
            list(repo.find_sources("foo", "1.0-1"))

    sid = PACKAGES.replace("trixie", "sid")
    assert adapter.urls == [
        PACKAGES + ".xz",
        sid + ".xz",
        sid + ".gz",
        sid,
        SOURCES + ".xz",
    ]
    assert parsed == [PACKAGES + ".xz"]
    # memoization is per repository instance (and thereby per run)
    assert next(make().find_binaries("foo", "1.0-1", "amd64"))
    assert adapter.urls[-1] == PACKAGES + ".xz"


def test_lookup_order(mirror):
    make, adapter = mirror
    contrib = PACKAGES.replace("/main/", "/contrib/")
    serve(adapter, PACKAGES, index(binary_paragraph(arch="arm64")))
    serve(adapter, contrib, index(binary_paragraph(filename="pool/contrib/foo.deb")))
    serve(adapter, PACKAGES.replace("trixie", "sid"), index(binary_paragraph()))
    repo = make(suites=["trixie", "sid"], components=["main", "contrib"])

    found = repo.find_binaries("foo", "1.0-1", "amd64")
    assert next(found).file.path == "pool/contrib/foo.deb"
    # later indexes are only retrieved when needed
    assert adapter.urls == [PACKAGES + ".xz", contrib + ".xz"]
    assert next(found).file.path == "pool/main/f/foo/foo_1.0-1_amd64.deb"
    assert adapter.urls[-1] == PACKAGES.replace("trixie", "sid") + ".xz"


@pytest.mark.parametrize(
    "name,version,arch,expected",
    [
        ("foo", "1:2.0-1", "amd64", "pool/epoch.deb"),
        ("foo", "2.0-1", "amd64", "pool/plain.deb"),
        ("foo", "2.0-1+b1", "amd64", "pool/binnmu.deb"),
        ("foo", "2.0-1", "all", None),
        ("foo", "2.0", "amd64", None),
        ("fo", "2.0-1", "amd64", None),
        ("Foo", "2.0-1", "amd64", None),
    ],
)
def test_exact_matching(mirror, name, version, arch, expected):
    make, adapter = mirror
    serve(
        adapter,
        PACKAGES,
        index(
            binary_paragraph(version="1:2.0-1", filename="pool/epoch.deb"),
            binary_paragraph(version="2.0-1", filename="pool/plain.deb"),
            binary_paragraph(version="2.0-1+b1", filename="pool/binnmu.deb"),
        ),
    )
    repo = make(architectures=["amd64"])
    found = [r.file.path for r in repo.find_binaries(name, version, arch)]
    assert found == ([expected] if expected else [])


@pytest.mark.parametrize("suite", ["./", "/"])
def test_flat_repository_root(mirror, suite):
    make, adapter = mirror
    serve(adapter, f"{ROOT}/Packages", index(binary_paragraph(filename="./foo_1.0-1_amd64.deb")))
    serve(adapter, f"{ROOT}/Sources", index(source_paragraph(directory=".")))
    repo = make(suites=[suite, "./"], components=[])
    binary = next(repo.find_binaries("foo", "1.0-1", "amd64"))
    assert binary.file.path == "foo_1.0-1_amd64.deb"
    assert repo.url_for(binary.file.path) == f"{ROOT}/foo_1.0-1_amd64.deb"
    source = next(repo.find_sources("foo", "1.0-1"))
    assert [f.path for f in source.files] == ["foo_1.0-1.dsc", "foo_1.0.orig.tar.gz"]
    # Architecture: all packages are listed in the same index
    assert list(repo.find_binaries("foo", "1.0-1", "all")) == []
    # both suites refer to the same index
    assert adapter.urls == [f"{ROOT}/Packages.xz", f"{ROOT}/Sources.xz"]


def test_flat_repository_path(mirror):
    """Paths in the index are relative to the archive root, not to the index."""
    make, adapter = mirror
    serve(
        adapter,
        f"{ROOT}/sub/dir/Packages",
        index(binary_paragraph(filename="sub/dir/foo+1_1.0-1_amd64.deb")),
    )
    serve(adapter, f"{ROOT}/sub/dir/Sources", index(source_paragraph(directory="sub/dir")))
    repo = make(suites=["./sub/dir/"], components=[])
    binary = next(repo.find_binaries("foo", "1.0-1", "amd64"))
    assert repo.url_for(binary.file.path) == f"{ROOT}/sub/dir/foo%2B1_1.0-1_amd64.deb"
    source = next(repo.find_sources("foo", "1.0-1"))
    assert repo.url_for(source.dsc.path) == f"{ROOT}/sub/dir/foo_1.0-1.dsc"
    assert list(repo.find_sources("bar", "1.0-1")) == []


def test_local_repository(fake_http, tmp_path):
    session, adapter = fake_http
    index_dir = tmp_path / "dists" / "trixie" / "main" / "binary-amd64"
    index_dir.mkdir(parents=True)
    (index_dir / "Packages.gz").write_bytes(gzip.compress(index(binary_paragraph())))
    for url in [tmp_path.as_uri(), f"file://localhost{tmp_path}"]:
        repo = RemoteRepository(session, url, ["trixie"], ["main"])
        assert next(repo.find_binaries("foo", "1.0-1", "amd64"))
        assert list(repo.find_sources("foo", "1.0-1")) == []
    assert adapter.requests == []
    (index_dir / "Packages.xz").mkdir()
    repo = RemoteRepository(session, tmp_path.as_uri(), ["trixie"], ["main"])
    with pytest.raises(RepositoryAccessError):
        next(repo.find_binaries("foo", "1.0-1", "amd64"))


@pytest.mark.parametrize(
    "location,allowed",
    [
        ("https://cdn.example.org/debian/Packages.xz", True),
        ("/elsewhere/Packages.xz", True),
        ("file:///etc/passwd", False),
        ("FILE://localhost/etc/passwd", False),
        ("http://cdn.example.org/debian/Packages.xz", False),
    ],
)
def test_redirects(mirror, tmp_path, location, allowed):
    make, adapter = mirror
    adapter.add(PACKAGES + ".xz", status=302, headers={"Location": location})
    data = xz(index(binary_paragraph()))
    adapter.add("https://cdn.example.org/debian/Packages.xz", data)
    adapter.add("https://mirror.example.org/elsewhere/Packages.xz", data)
    adapter.add("http://cdn.example.org/debian/Packages.xz", data)
    repo = make()
    if allowed:
        assert next(repo.find_binaries("foo", "1.0-1", "amd64"))
        assert len(adapter.requests) == 2
    else:
        with pytest.raises(RepositoryAccessError, match="refusing redirect"):
            next(repo.find_binaries("foo", "1.0-1", "amd64"))
        assert adapter.urls == [PACKAGES + ".xz"]


@pytest.mark.parametrize(
    "filename",
    [
        "/pool/foo.deb",
        "../foo.deb",
        "pool/../../foo.deb",
        "pool//foo.deb",
        "pool/./foo.deb",
        "https://evil.example.org/foo.deb",
        "//evil.example.org/foo.deb",
        "pool\\foo.deb",
        "pool/%2e%2e/foo.deb",
        "pool%2Ffoo.deb",
        "pool/.hidden.deb",
        "pool/foo\x1b.deb",
        ".",
    ],
)
def test_unsafe_filename(mirror, filename):
    make, adapter = mirror
    serve(adapter, PACKAGES, index(binary_paragraph(filename=filename)))
    with pytest.raises(RepositoryMetadataError, match="unsafe path"):
        next(make().find_binaries("foo", "1.0-1", "amd64"))


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("Size", "-1", "invalid size"),
        ("Size", "1e3", "invalid size"),
        ("Size", None, "no Filename or Size"),
        ("Filename", None, "no Filename or Size"),
        ("SHA256", "abc", "invalid sha256 checksum"),
        ("SHA256", "g" * 64, "invalid sha256 checksum"),
        ("MD5sum", "0" * 64, "invalid md5 checksum"),
    ],
)
def test_invalid_binary_record(mirror, field, value, match):
    make, adapter = mirror
    lines = [
        line
        for line in binary_paragraph().splitlines()
        if not line.startswith(f"{field}:") or value is not None
    ]
    if value is not None:
        lines = [f"{field}: {value}" if line.startswith(f"{field}:") else line for line in lines]
    serve(adapter, PACKAGES, index("\n".join(lines) + "\n"))
    with pytest.raises(RepositoryMetadataError, match=match):
        next(make().find_binaries("foo", "1.0-1", "amd64"))


def test_binary_without_checksum(mirror):
    make, adapter = mirror
    serve(adapter, PACKAGES, index(binary_paragraph(checksums=False)))
    with pytest.raises(RepositoryMetadataError, match="no supported checksum"):
        next(make().find_binaries("foo", "1.0-1", "amd64"))


def test_invalid_records_are_only_checked_when_used(mirror):
    make, adapter = mirror
    serve(
        adapter,
        PACKAGES,
        index(binary_paragraph(), binary_paragraph(name="bar", filename="../bar.deb")),
    )
    assert next(make().find_binaries("foo", "1.0-1", "amd64"))


@pytest.mark.parametrize(
    "fields",
    [
        ("Checksums-Sha256",),
        ("Files",),
        ("Checksums-Sha1", "Checksums-Sha256"),
        ("Files", "Checksums-Sha1", "Checksums-Sha256"),
    ],
)
def test_source_checksum_lists(mirror, fields):
    make, adapter = mirror
    serve(adapter, SOURCES, index(source_paragraph(fields=fields)))
    source = next(make().find_sources("foo", "1.0-1"))
    expected = {}
    for field in fields:
        algo = {
            "Files": ChecksumAlgo.MD5SUM,
            "Checksums-Sha1": ChecksumAlgo.SHA1SUM,
            "Checksums-Sha256": ChecksumAlgo.SHA256SUM,
        }[field]
        expected[algo] = LISTS[field](DSC)
    assert source.dsc.checksums == expected
    assert source.dsc.size == len(DSC)


@pytest.mark.parametrize(
    "paragraph,match",
    [
        (source_paragraph(directory="../pool"), "unsafe path"),
        (source_paragraph(directory="/pool"), "unsafe path"),
        (source_paragraph().replace("Directory: pool/main/f/foo\n", ""), "no Directory"),
        (source_paragraph(files={"foo_1.0.orig.tar.gz": TARBALL}), "exactly one .dsc"),
        (
            source_paragraph(files={"foo_1.0-1.dsc": DSC, "foo_1.0-2.dsc": DSC}),
            "exactly one .dsc",
        ),
        (source_paragraph(files={"foo_1.0-1.dsc": DSC, "../evil": TARBALL}), "unsafe file name"),
        (source_paragraph(files={"foo_1.0-1.dsc": DSC, "a/b": TARBALL}), "unsafe file name"),
        (
            source_paragraph(files={"foo_1.0-1.dsc": DSC})
            + f" {sha256(DSC)} {len(DSC)} foo_1.0-1.dsc\n",
            "lists 'foo_1.0-1.dsc' twice",
        ),
        (
            source_paragraph().replace(
                " " + str(len(TARBALL)) + " foo_1.0.orig", " 1 foo_1.0.orig", 1
            ),
            "conflicting sizes",
        ),
        (
            source_paragraph() + f" {sha256(b'')} 0 foo_1.0.orig.tar.gz.asc\n",
            "not listed in Files",
        ),
        (source_paragraph().replace(f" {md5(DSC)} ", f" {md5(DSC)}  extra ", 1), "invalid Files"),
        (source_paragraph(files={}), "no files listed"),
    ],
)
def test_invalid_source_record(mirror, paragraph, match):
    make, adapter = mirror
    serve(adapter, SOURCES, index(paragraph))
    with pytest.raises(RepositoryMetadataError, match=match):
        next(make().find_sources("foo", "1.0-1"))


def test_source_without_files_field(mirror):
    """Without Files, the files of all lists are combined and checked for consistency."""
    make, adapter = mirror
    paragraph = source_paragraph(fields=["Checksums-Sha256"]) + (
        f"Checksums-Sha1:\n {sha1(DSC)} {len(DSC)} foo_1.0-1.dsc\n"
        f" {sha1(b'sig')} 3 foo_1.0.orig.tar.gz.asc\n"
    )
    serve(adapter, SOURCES, index(paragraph))
    source = next(make().find_sources("foo", "1.0-1"))
    assert [f.name for f in source.files] == [
        "foo_1.0-1.dsc",
        "foo_1.0.orig.tar.gz.asc",
        "foo_1.0.orig.tar.gz",
    ]
    assert source.dsc.checksums == {
        ChecksumAlgo.SHA1SUM: sha1(DSC),
        ChecksumAlgo.SHA256SUM: sha256(DSC),
    }

    paragraph = paragraph.replace(f" {len(DSC)} foo_1.0-1.dsc", " 1 foo_1.0-1.dsc", 1)
    serve(adapter, SOURCES.replace("trixie", "sid"), index(paragraph))
    with pytest.raises(RepositoryMetadataError, match="conflicting sizes"):
        next(make(suites=["sid"]).find_sources("foo", "1.0-1"))


RELEASE = f"{ROOT}/dists/trixie/Release"
INRELEASE = f"{ROOT}/dists/trixie/InRelease"
BINARY_ALL = f"{ROOT}/dists/trixie/main/binary-all/Packages"
BINARY_ARM64 = f"{ROOT}/dists/trixie/main/binary-arm64/Packages"


def release(architectures, no_support=None):
    text = f"Origin: Test\nSuite: trixie\nArchitectures: {architectures}\n"
    if no_support:
        text += f"No-Support-for-Architecture-all: {no_support}\n"
    return text.encode()


@pytest.mark.parametrize(
    "architectures,release_file,searched",
    [
        # Debian: Architecture: all packages are listed in the native indexes
        ([], release("all amd64 arm64", "Packages"), [PACKAGES, BINARY_ARM64]),
        ([], release("amd64 arm64"), [PACKAGES, BINARY_ARM64]),
        # Architecture: all packages are listed in a separate index
        ([], release("all amd64 arm64"), [BINARY_ALL, PACKAGES, BINARY_ARM64]),
        ([], release("all"), [BINARY_ALL]),
        (["arm64"], release("all amd64 arm64", "Packages"), [BINARY_ARM64]),
        (["arm64"], release("all amd64 arm64"), [BINARY_ALL, BINARY_ARM64]),
        # without a Release file, a binary-all index is optional
        (["arm64", "amd64"], None, [BINARY_ALL, BINARY_ARM64, PACKAGES]),
        # explicitly configured, the Release file is not needed
        (["all"], None, [BINARY_ALL]),
        (["arm64", "all"], None, [BINARY_ARM64, BINARY_ALL]),
    ],
)
def test_architecture_all_indexes(mirror, architectures, release_file, searched):
    make, adapter = mirror
    if release_file:
        adapter.add(RELEASE, release_file)
    repo = make(architectures=architectures)
    assert list(repo.find_binaries("foo", "1.0-1", "all")) == []
    indexes = [url for url in adapter.urls if url.endswith(".xz")]
    assert indexes == [url + ".xz" for url in searched]
    if "all" in architectures:
        assert RELEASE not in adapter.urls


def test_architecture_all_lookup(mirror):
    make, adapter = mirror
    adapter.add(RELEASE, release("all amd64 arm64", "Packages"))
    serve(adapter, PACKAGES, index(binary_paragraph(), binary_paragraph(name="bar", arch="all")))
    repo = make()
    assert list(repo.find_binaries("foo", "1.0-1", "all")) == []
    found = next(repo.find_binaries("bar", "1.0-1", "all"))
    assert found.file.path == "pool/main/f/bar/bar_1.0-1_all.deb"
    # the Release file is retrieved once, the native architecture does not need it
    assert next(repo.find_binaries("foo", "1.0-1", "amd64"))
    assert adapter.urls.count(RELEASE) == 1
    assert adapter.urls.count(PACKAGES + ".xz") == 1


def test_architecture_all_from_inrelease(mirror):
    make, adapter = mirror
    signed = (
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        + release("all amd64 arm64", "Packages")
        + b"-----BEGIN PGP SIGNATURE-----\n\nnot verified\n-----END PGP SIGNATURE-----\n"
    )
    adapter.add(INRELEASE, signed)
    repo = make()
    assert list(repo.find_binaries("foo", "1.0-1", "all")) == []
    assert adapter.urls[:2] == [RELEASE, INRELEASE]
    assert BINARY_ALL + ".xz" not in adapter.urls


@pytest.mark.parametrize(
    "release_file,match",
    [
        (None, "no Release file"),
        (b"Origin: Test\n", "no Release file"),
        (release("all", "Packages"), "lists no index"),
    ],
)
def test_architecture_all_unknown(mirror, release_file, match):
    make, adapter = mirror
    if release_file:
        adapter.add(INRELEASE, release_file)
    repo = make()
    for _ in range(2):
        with pytest.raises(RepositoryConfigurationError, match=match):
            next(repo.find_binaries("foo", "1.0-1", "all"))
    # no index is searched and the Release file is retrieved once
    assert adapter.urls == [RELEASE, INRELEASE]


@pytest.mark.parametrize(
    "status,body,error",
    [
        (500, b"", RepositoryAccessError),
        (200, release("all amd64 $(ARCH)"), RepositoryMetadataError),
        (200, b"Architectures: amd64 \xff\n", RepositoryMetadataError),
    ],
)
def test_release_errors(mirror, status, body, error):
    make, adapter = mirror
    adapter.add(RELEASE, body, status=status)
    with pytest.raises(error):
        next(make(architectures=["amd64"]).find_binaries("foo", "1.0-1", "all"))


def test_invalid_package_architecture(mirror):
    make, adapter = mirror
    with pytest.raises(RepositoryError, match="invalid architecture"):
        next(make().find_binaries("foo", "1.0-1", "../amd64"))
    assert adapter.requests == []


def test_fetch(mirror):
    make, adapter = mirror
    adapter.add(f"{ROOT}/pool/foo_1.0%2B1.dsc", DSC)
    repo = make()
    assert repo.fetch("pool/foo_1.0+1.dsc", len(DSC)) == DSC
    with pytest.raises(RepositoryMetadataError, match="size limit"):
        repo.fetch("pool/foo_1.0+1.dsc", len(DSC) - 1)
    with pytest.raises(RepositoryAccessError, match="not available"):
        repo.fetch("pool/bar.dsc", 100)
