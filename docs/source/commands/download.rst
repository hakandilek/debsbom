``download`` command
====================

.. automodule:: debsbom.commands.download.DownloadCmd

.. argparse::
    :module: debsbom.cli
    :func: setup_parser
    :prog: debsbom
    :path: download

Resolvers
---------

Before anything is downloaded, all selected packages are resolved: the resolver selected with ``--resolver`` determines the files of each package and the locations to download them from.

*   ``debian-snapshot`` (default): looks up packages on the Debian snapshot archive (snapshot.debian.org).
*   ``debian-mirror``: looks up packages in the indexes of an APT repository, like a Debian mirror or a repository created by tools such as ``reprepro``.

Further resolvers can be provided by plugins. Packages that are excluded with ``--sources``, ``--binaries`` or ``--skip-pkgs`` are filtered before they are resolved, so no resolver receives any information about them.

A package that cannot be resolved, because it is not found or because of an error, is reported with a warning that states the reason, and with the status ``not_found`` in the JSON output. The other packages are still downloaded.

APT Repositories
~~~~~~~~~~~~~~~~

The ``debian-mirror`` resolver looks up packages in a single APT repository, which is configured by its archive root (``--mirror-url``), and the suites (``--mirror-suite``) and components (``--mirror-component``) to search:

.. code-block:: bash

    debsbom --json download \
      --resolver debian-mirror \
      --mirror-url https://deb.debian.org/debian \
      --mirror-suite trixie \
      --mirror-component main \
      --mirror-architecture amd64 \
      --snapshot-fallback \
      sbom.spdx.json

The archive root is an ``http``, ``https`` or ``file`` URL (with an absolute path), without credentials, query or fragment. The options are validated before any input is read and before any request is made.

Suites and components can be repeated. They are searched in the given order, suite by suite, and the first matching package is used. The indexes of a suite are located below ``dists``:

*   ``<root>/dists/<suite>/<component>/source/Sources``
*   ``<root>/dists/<suite>/<component>/binary-<arch>/Packages``

A suite ending with ``/`` is an exact path relative to the archive root, as used by flat repositories, e.g. ``./`` or ``sub/dir/``. Its indexes are ``<root>/<path>/Sources`` and ``<root>/<path>/Packages``, and it has no components. Suites with and without exact path cannot be combined.

Each index is retrieved in the first available variant: compressed with xz, compressed with gzip, or uncompressed. A missing index is treated like an empty one, so incomplete repositories are supported, e.g. repositories created by ``reprepro`` with only some packages or architectures, or without sources. The files are located by the paths in the indexes (``Directory`` and ``Filename``), which are relative to the archive root.

Only one archive root is searched. Debian security updates are published in a separate archive, e.g. with the archive root ``https://security.debian.org/debian-security`` and the suite ``trixie-security``, which is not searched automatically.

Packages are matched exactly by name and full version, including epoch and binNMU suffix, and binary packages also by architecture. Other versions are never used, and the suites are not derived from the SBOM. If the SBOM contains checksums of a package, packages of the repository with a different checksum are ignored. The strongest algorithm known to both is compared (``SHA512``, ``SHA256``, ``SHA1``, ``MD5``). Without checksums, the first matching package is used.

For a source package, the ``.dsc`` file is retrieved while resolving. It must match the size and checksum in the index and the checksum of the package in the SBOM, if any, and it must describe the same source package and the same files as the index. Then the ``.dsc`` file and all files it lists, e.g. multiple upstream tarballs and their signatures, are downloaded together into one directory. A ``.dsc`` file with a different checksum than in the SBOM is not accepted, even if only its signature differs. Without a checksum in the SBOM, the identity of a source package is imprecise and the first matching one of the repository is used.

Binary packages of the architecture ``all`` are listed either in the indexes of all architectures of a suite, or in a separate ``binary-all`` index. Like apt, the resolver searches the ``binary-all`` index if the ``Release`` file of the suite announces it (``all`` in ``Architectures``, unless ``No-Support-for-Architecture-all: Packages`` is set) or if the suite has no ``Release`` file, followed by the indexes of the architectures given with ``--mirror-architecture`` or, without this option, of the architectures listed in the ``Release`` file. If ``all`` is given with ``--mirror-architecture``, exactly the given indexes are searched. If no architecture is known, the package cannot be resolved: the architecture of the host is never assumed. Binary packages of other architectures are only searched in the index of their architecture. Suites with an exact path have a single ``Packages`` index for all architectures.

Snapshot Fallback
~~~~~~~~~~~~~~~~~

A mirror usually only provides the latest versions of packages. With ``--snapshot-fallback``, packages that are not found in the repository are looked up on snapshot.debian.org. This sends the names and versions of these packages to snapshot.debian.org, which is why there is no fallback by default (``--no-snapshot-fallback``). Packages found in the repository, and packages excluded with ``--skip-pkgs``, are not looked up there.

Only packages that are not found fall back: the repository has no package with that name, version and architecture, or only ones with a different checksum than in the SBOM. Errors are reported instead of being hidden by the fallback, e.g. authentication or server errors, timeouts, malformed or unsafe metadata, and data that contradicts its metadata. All files of a package are resolved by the same resolver, so a source package never consists of files of both the repository and snapshot.debian.org.

The fallback only applies to resolving. All packages are resolved before the download starts. If a file of the repository cannot be downloaded afterwards, e.g. because it was removed from the mirror in the meantime, the download fails with an error, and the file is not downloaded from snapshot.debian.org instead.

Caching
~~~~~~~

The ``debian-snapshot`` resolver stores its results, including packages that are not found, in ``<outdir>/.cache/debian-snapshot``. This cache is also used by the Snapshot fallback.

Results of the ``debian-mirror`` resolver are not stored, as this cache is keyed by the package only, not by the repository configuration, and the content of a repository changes over time. Instead, each index is retrieved and parsed at most once per run. Errors when retrieving or parsing an index are remembered as well, but only until the end of the run.

Trust and Limits
~~~~~~~~~~~~~~~~

The ``debian-mirror`` resolver validates the repository metadata it uses: the indexes must be well-formed and contain only safe relative paths, consistent sizes and well-formed checksums, and every file must have a checksum of a supported algorithm. Each downloaded file is verified against its size and checksum in the index, and binary packages and ``.dsc`` files also against the checksum in the SBOM. This detects corrupted and inconsistent data, but it does not authenticate the repository: neither the signatures of the ``Release`` and ``InRelease`` files nor the checksums of the indexes listed there are verified. The ``Release`` file is only used to find the indexes of packages of the architecture ``all``. Thus, the repository, or anybody who can modify the connection to it, can provide other packages with consistent metadata, which is only detected by checksums in the SBOM. Verifying the signatures of repositories is tracked in `issue #282 <https://github.com/siemens/debsbom/issues/282>`__.

Redirects to other protocols than HTTP and HTTPS are refused. While resolving, requests are not redirected from HTTPS to HTTP, and they time out after 10 seconds while connecting and after 60 seconds without data. Indexes are limited to 128 MiB compressed and 512 MiB uncompressed (decompressing xz data uses at most 256 MiB of memory), ``Release`` and ``InRelease`` files to 16 MiB, and ``.dsc`` files to 4 MiB.

Download Locations
~~~~~~~~~~~~~~~~~~

Files are stored in ``<outdir>/sources/<archive>/`` and ``<outdir>/binaries/<archive>/``. For the ``debian-mirror`` resolver, ``<archive>`` is derived from the repository URL, e.g. ``mirror_deb.debian.org_debian``, while files found on snapshot.debian.org are stored as with the ``debian-snapshot`` resolver, e.g. in ``debian``. All files of a source package are stored in the same directory, as required by the ``source-merge`` command. The names of the directories only group the files, they do not state the origin of the packages.

The ``source`` of a download result in the JSON output is the URL that was selected by the resolver to download the file from. It is not necessarily a permanent location, as mirrors remove old versions, it does not state the origin of the package, and it does not prove that the file was retrieved in this run, as it may have been in the download directory already.

JSON Output Schema
------------------

When the application is run with JSON output enabled (via the ``--json`` flag),
status messages are emitted as single-line JSON objects to standard output.
Each line represents a distinct package download operation.

The schema for these JSON objects is as follows:

.. literalinclude:: ../../../src/debsbom/schema/schema-download.json
   :language: json

Fields
~~~~~~

*   **status**:
    The status of the download operation. This field will contain one of the
    following predefined values from the :py:class:`DownloadStatus` enum:

    *   ``"ok"``: The file was either successfully downloaded or found in the download directory, and its size and checksums were verified, as far as they are known.
    *   ``"checksum_mismatch"``: The size or checksum of the file did not match the one given by the resolver, or the checksum of the package in the SBOM.
    *   ``"not_found"``: The package could not be resolved, because it was not found or because of an error.

*   **package**:
    An object identifying the package, including the name and the version as a string.

*   **filename**:
    The name of the processed file or an empty string if the package is unavailable.

*   **path**:
    The absolute path to the downloaded file or an empty string if nothing could be downloaded.

*   **source**:
    The URL that was selected by the resolver to download the file from, or an empty string if the package could not be resolved (see `Download Locations`_).
