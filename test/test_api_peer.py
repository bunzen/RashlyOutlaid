import pytest
import responses

import RashlyOutlaid.api as shadowserver

query_responses = {
    "212.58.245.94": {
        "url": "https://api.shadowserver.org/net/asn?peer=212.58.245.94",
        "response": [
            {
                "ip": "212.58.245.94",
                "geo": "GB",
                "asn": "2818",
                "prefix": "212.58.224.0/19",
                "peer": "1103 1299 2914 4657 8220 9002 42708 58511",
                "asname_short": "AS2818",
                "asname_long": "BBC",
            }
        ],
        "status": 200,
    }
}


@responses.activate
def test_query() -> None:

    responses.add(
        responses.GET,
        query_responses["212.58.245.94"]["url"],
        json=query_responses["212.58.245.94"]["response"],
        status=query_responses["212.58.245.94"]["status"],
    )

    result = shadowserver.peer(["212.58.245.94"])[0]

    assert isinstance(result.asname, str)
    assert isinstance(result.asn, str)
    assert isinstance(result.cn, str)
    assert isinstance(result.isp, str)
    assert isinstance(result.peers[0], str)
    assert isinstance(result.prefix, str)
    assert result.asn == "2818"
    assert result.asname == "AS2818"
    assert result.cn == "GB"
    assert result.isp == "BBC"
    assert result.peers == [
        "1103",
        "1299",
        "2914",
        "4657",
        "8220",
        "9002",
        "42708",
        "58511",
    ]
    assert result.prefix == "212.58.224.0/19"
