# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable
import errno
from io import BytesIO
import locale
from pathlib import Path
from requests import Response, Request, Session, codes
from requests.adapters import BaseAdapter
from requests.exceptions import RequestException
from urllib.parse import unquote, urljoin, urlparse, urlsplit


class UnsafeRedirectError(RequestException):
    """A redirect to a location with an unsupported or less secure scheme was refused."""


def redirect_guard(allow_downgrade: bool = True) -> Callable[..., Response]:
    """
    Create a response hook which refuses to follow redirects to anything but HTTP(S) URLs,
    e.g. into the local file transport. Unless ``allow_downgrade`` is set, redirects from
    HTTPS to plain HTTP are refused as well.
    """

    def hook(response: Response, *args, **kwargs) -> Response:
        if not response.is_redirect:
            return response
        target = urljoin(response.url, response.headers["Location"])
        scheme = urlsplit(target).scheme.lower()
        downgrade = scheme == "http" and urlsplit(response.url).scheme.lower() == "https"
        if scheme not in ("http", "https") or (downgrade and not allow_downgrade):
            response.close()
            raise UnsafeRedirectError(
                f"refusing redirect from '{response.url}' to '{target}'", response=response
            )
        return response

    return hook


class LocalFileAdapter(BaseAdapter):
    """Adapter for local file access."""

    def send(self, request, **kwargs) -> Response:
        if request.method != "GET":
            raise ValueError(f"Request method {request.method} is not supported")

        response = Response()
        response.request = request
        response.url = request.url

        path = Path(unquote(urlparse(request.url).path))
        try:
            response.raw = open(path, "rb")
            # make sure we properly close the file when we are done
            response.raw.release_conn = response.raw.close
            response.status_code = codes.ok
        except IOError as e:
            if e.errno == errno.EACCES:
                response.status_code = codes.forbidden
            elif e.errno == errno.ENOENT:
                response.status_code = codes.not_found
            else:
                response.status_code = codes.bad_request
            response.raw = BytesIO(str(e).encode(locale.getpreferredencoding()))
            response.reason = str(e)

        return response

    def close(self):
        pass
