import pytest
import responses

import RashlyOutlaid.api as shadowserver

query_responses = {
    "2818": {
        "url": "https://api.shadowserver.org/net/asn?query=2818",
        "response": {
            "asn": "2818",
            "asname_short": "AS2818",
            "date": "19931118",
            "asname_long": "BBC",
            "nic": "RIPENCC",
            "geo": "GB",
        },
        "status": 200,
    }
}


@responses.activate
def test_query() -> None:

    responses.add(
        responses.GET,
        query_responses["2818"]["url"],
        json=query_responses["2818"]["response"],
        status=query_responses["2818"]["status"],
    )

    result = shadowserver.asn("2818")[0]

    assert isinstance(result.asname, str)
    assert isinstance(result.asn, str)
    assert isinstance(result.cn, str)
    assert isinstance(result.isp, str)
    assert result.asn == "2818"
    assert result.asname == "AS2818"
    assert result.cn == "GB"
    assert result.isp == "BBC"
