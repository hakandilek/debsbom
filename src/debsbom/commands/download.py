# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

# Annotations reference the optional download dependencies, which may be missing.
from __future__ import annotations

from importlib.metadata import entry_points, version

import argparse
from collections import deque
from collections.abc import Iterable
from io import BytesIO
import logging
from pathlib import Path

from .input import PkgStreamInput, SbomInput, SourceBinaryInput
from ..dpkg.package import Package
from ..resolver.resolver import PackageStreamResolver
from ..util.progress import progress_cb

try:
    # Attempt to import unused zstandard dependency to check their availability.
    # If it is missing, dependent modules are skipped to prevent import errors.
    from zstandard import ZstdCompressor, ZstdDecompressor
    import requests
    from ..apt.remote import RemoteRepository
    from ..snapshot import client as sdlclient
    from ..download.adapters import LocalFileAdapter
    from ..download.download import PackageDownloader, DownloadStatus, DownloadResult
    from ..download.mirror import MirrorResolver
    from ..download.resolver import (
        FallbackResolver,
        PackageResolverCache,
        PersistentResolverCache,
        ResolveError,
        Resolver,
    )
except ModuleNotFoundError:
    pass


logger = logging.getLogger(__name__)


def setup_snapshot_resolver(session):
    sdl = sdlclient.SnapshotDataLake(session=session)
    return sdlclient.UpstreamResolver(sdl)


def setup_mirror_resolver(session, url, suites, components=(), architectures=()):
    """
    Create the built-in ``debian-mirror`` resolver. Unlike the factories of resolver
    plugins, it takes the repository configuration of the ``--mirror-*`` options.
    The configuration is validated, but no request is made.
    """
    return MirrorResolver(RemoteRepository(session, url, suites, components, architectures))


RESOLVERS = {"debian-snapshot": setup_snapshot_resolver, "debian-mirror": setup_mirror_resolver}

resolver_endpoints = entry_points(group="debsbom.download.resolver")
for ep in resolver_endpoints:
    setup_fn = ep.load()
    RESOLVERS[ep.name] = setup_fn

#: options of the built-in debian-mirror resolver
MIRROR_OPTIONS = (
    "mirror_url",
    "mirror_suite",
    "mirror_component",
    "mirror_architecture",
    "snapshot_fallback",
)


class DownloadInput(SbomInput):
    """
    Abstract class for download commands.
    Does not live in the inputs module as the dependency import logic depends on
    it being imported from here.
    """

    @staticmethod
    def human_readable_bytes(size):
        if size < 1024 * 1024:
            return f"{int(size / 1024):d} KiB"
        elif size < 1024 * 1024 * 1024:
            return f"{int(size / 1024 / 1024):d} MiB"
        else:
            return f"{size / 1024 / 1024 / 1024:.2f} GiB"

    @staticmethod
    def _check_for_dsc(p, files):
        """
        all source packages should have a .dsc file. Warn if it is missing
        """
        if p.is_source() and not any(f.filename == p.dscfile() for f in files):
            logger.warning(f"no .dsc file found for {p}")

    @staticmethod
    def _create_default_session() -> requests.Session:
        rs = requests.Session()
        rs.mount("file:///", LocalFileAdapter())
        rs.headers.update({"User-Agent": f"debsbom/{version('debsbom')}"})
        return rs

    @staticmethod
    def _check_resolver_args(args) -> None:
        """Validate the combination of resolver options, before anything is done."""
        given = [o for o in MIRROR_OPTIONS if getattr(args, o, None) is not None]
        if RESOLVERS.get(args.resolver) is not setup_mirror_resolver:
            # also if a plugin replaces the debian-mirror resolver, as it cannot be configured
            if given:
                option = given[0]
                if option == "snapshot_fallback" and not args.snapshot_fallback:
                    option = "no_snapshot_fallback"
                option = "--" + option.replace("_", "-")
                raise ValueError(f"{option} requires the built-in 'debian-mirror' resolver")
            return
        if not args.mirror_url:
            raise ValueError("the 'debian-mirror' resolver requires --mirror-url")
        if not args.mirror_suite:
            raise ValueError("the 'debian-mirror' resolver requires at least one --mirror-suite")

    @staticmethod
    def _create_snapshot_fallback(session, outdir) -> Resolver:
        """
        Create the built-in Snapshot resolver for the fallback of the debian-mirror resolver.
        It shares the persistent cache of the debian-snapshot resolver, unless a plugin
        replaces that one and owns its cache.
        """
        resolver = setup_snapshot_resolver(session)
        if RESOLVERS.get("debian-snapshot") is setup_snapshot_resolver:
            cachedir = outdir / ".cache"
            cachedir.mkdir(exist_ok=True)
            resolver.cache = PersistentResolverCache(cachedir / "debian-snapshot")
        return resolver

    @staticmethod
    def _create_default_resolver(args, session, outdir) -> Resolver:
        DownloadInput._check_resolver_args(args)
        setup_fn = RESOLVERS[args.resolver]
        if setup_fn is setup_mirror_resolver:
            # Not cached persistently: the cache is keyed by the package only, not by the
            # repository configuration, and a repository changes over time.
            try:
                u_resolver = setup_mirror_resolver(
                    session,
                    args.mirror_url,
                    args.mirror_suite,
                    args.mirror_component or (),
                    args.mirror_architecture or (),
                )
            except ValueError as e:
                raise ValueError(f"invalid mirror configuration: {e}") from e
            # only packages the repository does not have may be looked up on snapshot
            if args.snapshot_fallback:
                fallback = DownloadInput._create_snapshot_fallback(session, outdir)
                u_resolver = FallbackResolver(u_resolver, fallback)
            return u_resolver
        u_resolver = setup_fn(session)
        if type(u_resolver.cache) is PackageResolverCache:
            cachedir = outdir / ".cache"
            cachedir.mkdir(exist_ok=True)
            cache = PersistentResolverCache(cachedir / args.resolver)
            u_resolver.cache = cache
        return u_resolver

    @staticmethod
    def _download_packages(
        downloader: PackageDownloader,
        resolver_cache: Resolver,
        pkgs: list[Package],
        progress: bool | None,
        json: bool | None,
    ) -> Iterable[DownloadResult]:
        logger.info("Resolving upstream packages...")
        for idx, pkg in enumerate(pkgs):
            if progress:
                progress_cb(idx, len(pkgs), pkg.name)
            try:
                files = list(resolver_cache._resolve_pkg(pkg))
                DownloadCmd._check_for_dsc(pkg, files)
                downloader.register(files, pkg)
            except ResolveError as e:
                pkg_type = "source" if pkg.is_source() else "binary"
                reason = f": {e}" if str(e) else ""
                logger.warning(f"failed to resolve {pkg_type} package: {pkg}{reason}")
                if json:
                    print(
                        DownloadResult(
                            path=None,
                            status=DownloadStatus.NOT_FOUND,
                            package=pkg,
                            filename="",
                            source="",
                        ).json()
                    )

        if not json:
            nfiles, nbytes, cfiles, cbytes = downloader.stat()
            print(
                f"downloading {nfiles} files, {DownloadCmd.human_readable_bytes(nbytes)} "
                f"(cached: {cfiles}, {DownloadCmd.human_readable_bytes(cbytes)})"
            )

        dl_results = downloader.download(progress_cb=progress_cb if progress else None)

        for r in dl_results:
            if json:
                print(r.json())
            logger.debug(f"{r.status}: {r.filename}")
            yield r

    @classmethod
    def parser_add_download_args(cls, parser):
        from ..cli import arg_mark_as_dir

        cls.parser_add_sbom_input_args(parser)
        arg_mark_as_dir(
            parser.add_argument(
                "--outdir", default="downloads", help="directory to store downloaded files"
            )
        )
        parser.add_argument(
            "--resolver",
            choices=RESOLVERS.keys(),
            default="debian-snapshot",
            help="resolver to use to find upstream packages (default: %(default)s)",
        )
        mirror = parser.add_argument_group(
            "debian-mirror resolver",
            "Options of the 'debian-mirror' resolver, which looks up packages in the indexes "
            "of an APT repository, like a Debian mirror. The repository metadata is validated, "
            "but its signatures are not verified.",
        )
        mirror.add_argument(
            "--mirror-url",
            metavar="URL",
            help="archive root of the repository (http, https or file URL), "
            "e.g. https://deb.debian.org/debian",
        )
        mirror.add_argument(
            "--mirror-suite",
            metavar="SUITE",
            action="append",
            help="suite to search, e.g. trixie. Can be repeated, suites are searched in order. "
            "A suite ending with '/' is an exact path relative to the archive root (flat "
            "repository), e.g. './'",
        )
        mirror.add_argument(
            "--mirror-component",
            metavar="COMPONENT",
            action="append",
            help="component to search in each suite, e.g. main. Can be repeated, components "
            "are searched in order. Required for suites without exact path",
        )
        mirror.add_argument(
            "--mirror-architecture",
            metavar="ARCH",
            action="append",
            help="architecture of the indexes to search for 'Architecture: all' packages. "
            "Can be repeated (default: the architectures of the Release file of the suite)",
        )
        mirror.add_argument(
            "--snapshot-fallback",
            action=argparse.BooleanOptionalAction,
            help="look up packages that are not found in the repository on "
            "snapshot.debian.org, which receives the names and versions of these packages. "
            "Repository errors do not fall back (default: no fallback)",
        )


class DownloadCmd(DownloadInput, SourceBinaryInput, PkgStreamInput):
    """
    Processes a SBOM and downloads the referenced packages.
    If no SBOM is provided, it reads line separated entries (name version arch)
    from stdin to define what shall be downloaded.
    """

    @classmethod
    def run(cls, args):
        cls._check_resolver_args(args)
        outdir = Path(args.outdir)
        outdir.mkdir(exist_ok=True)
        rs = DownloadCmd._create_default_session()
        # the resolver configuration is validated before any input is read
        u_resolver = cls._create_default_resolver(args, rs, outdir)
        if cls.has_bomin(args):
            resolvers = cls.get_sbom_resolvers(args)
        else:
            resolvers = [cls.get_pkgstream_resolver()]
        downloader = PackageDownloader(args.outdir, session=rs)

        if args.skip_pkgs:
            skip = list(PackageStreamResolver(BytesIO(args.skip_pkgs.encode())))
        else:
            skip = None

        pkgs = []
        for resolver in resolvers:
            pkgs.extend(
                list(
                    filter(
                        lambda p: cls._filter_pkg(p, args.sources, args.binaries, skip), resolver
                    )
                )
            )

        # immediately drop the results, we just need to exhaust the iterator
        deque(
            cls._download_packages(downloader, u_resolver, pkgs, args.progress, args.json), maxlen=0
        )

    @classmethod
    def setup_parser(cls, parser):
        cls.parser_add_download_args(parser)
        cls.parser_add_source_binary_args(parser)
        parser.add_argument(
            "--skip-pkgs",
            metavar="SKIP",
            help="packages to exclude from the download, in package-list format",
        )
