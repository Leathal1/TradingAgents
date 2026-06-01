import asyncio
import aiohttp
from aiohttp.http_parser import HttpResponseParser
import pytest


def test_aiohttp_version():
    """Assert that aiohttp version is >= 3.13.4."""
    version = tuple(map(int, aiohttp.__version__.split('.')[:3]))
    assert version >= (3, 13, 4), (
        f"aiohttp version is {aiohttp.__version__}, but >=3.13.4 is required"
    )


@pytest.mark.asyncio
async def test_aiohttp_rejects_null_bytes_in_response_header_values():
    """
    Regression test for CVE-2026-34520.

    Prior to aiohttp 3.13.4, the llhttp C parser accepted null bytes
    and control characters in HTTP response header values, enabling
    header injection / response splitting. This test asserts that the
    parser raises a BadHttpMessage (or similar error) when presented
    with a null byte in a response header value.
    """
    # Feed a minimal raw HTTP response containing a null byte in a header value.
    raw_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"X-Custom: foo\x00bar\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )

    loop = asyncio.get_event_loop()
    proto = HttpResponseParser(
        aiohttp.http_writer.HttpVersion11,
        aiohttp.ClientResponse,
        timer=None,
        payload_exception=None,
        mode="body",
        lax=False,
        loop=loop,
    )

    # llhttp in >=3.13.4 must reject null bytes in header values.
    with pytest.raises(aiohttp.http_exceptions.BadHttpMessage):
        proto.feed_data(raw_response)


def test_aiohttp_rejects_control_characters_in_response_header_values():
    """
    Ensure that control characters (e.g. \x01) in header values are
    also rejected by the parser.
    """
    raw_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"X-Custom: foo\x01bar\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )

    loop = asyncio.get_event_loop()
    proto = HttpResponseParser(
        aiohttp.http_writer.HttpVersion11,
        aiohttp.ClientResponse,
        timer=None,
        payload_exception=None,
        mode="body",
        lax=False,
        loop=loop,
    )

    with pytest.raises(aiohttp.http_exceptions.BadHttpMessage):
        proto.feed_data(raw_response)
