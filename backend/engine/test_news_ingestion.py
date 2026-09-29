from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from backend.engine.news_ingestion import DynamicNewsIngestor


def test_empty_rss_uses_transport_mode_fallbacks():
    ingestor = DynamicNewsIngestor()

    with patch("backend.engine.news_ingestion.urllib.request.urlopen") as urlopen, patch(
        "backend.engine.news_ingestion.feedparser.parse",
        return_value=SimpleNamespace(entries=[]),
    ):
        urlopen.return_value.__enter__.return_value = object()
        for mode, expected in ingestor.fallback_news.items():
            assert ingestor.get_latest_news("Test Location", mode) == expected

    queries = [
        parse_qs(urlsplit(call.args[0]).query)["q"][0]
        for call in urlopen.call_args_list
    ]
    assert queries == [
        "Test Location maritime logistics disruption",
        "Test Location aviation cargo logistics disruption",
        "Test Location highway logistics disruption",
        "Test Location rail freight logistics disruption",
    ]


def test_rss_failure_uses_transport_mode_fallback():
    ingestor = DynamicNewsIngestor()

    with patch(
        "backend.engine.news_ingestion.urllib.request.urlopen",
        side_effect=RuntimeError("mocked RSS failure"),
    ):
        assert ingestor.get_latest_news("Test Location", " AIR ") == ingestor.fallback_news["air"]


def test_identical_request_uses_cached_news():
    ingestor = DynamicNewsIngestor()
    first_feed = SimpleNamespace(entries=[SimpleNamespace(title="First headline")])

    with patch("backend.engine.news_ingestion.urllib.request.urlopen") as urlopen, patch(
        "backend.engine.news_ingestion.feedparser.parse",
        return_value=first_feed,
    ) as parse:
        urlopen.return_value.__enter__.return_value = object()
        first = ingestor.get_latest_news("Test Location", "SEA")
        repeated = ingestor.get_latest_news("Test Location", " sea ")

    assert first == repeated == "First headline"
    assert parse.call_count == 1
    assert urlopen.call_count == 1


def test_different_queries_do_not_share_cached_news():
    ingestor = DynamicNewsIngestor()
    feeds = [
        SimpleNamespace(entries=[SimpleNamespace(title="Sea headline")]),
        SimpleNamespace(entries=[SimpleNamespace(title="Air headline")]),
    ]

    with patch("backend.engine.news_ingestion.urllib.request.urlopen") as urlopen, patch(
        "backend.engine.news_ingestion.feedparser.parse",
        side_effect=feeds,
    ) as parse:
        urlopen.return_value.__enter__.return_value = object()
        sea = ingestor.get_latest_news("Test Location", "sea")
        air = ingestor.get_latest_news("Other Location", "air")

    assert sea == "Sea headline"
    assert air == "Air headline"
    assert parse.call_count == 2


def test_expired_cache_fetches_fresh_news():
    ingestor = DynamicNewsIngestor()
    feeds = [
        SimpleNamespace(entries=[SimpleNamespace(title="Cached headline")]),
        SimpleNamespace(entries=[SimpleNamespace(title="Fresh headline")]),
    ]

    with patch("backend.engine.news_ingestion.time.time", side_effect=[1000.0, 1899.0, 1901.0]), patch(
        "backend.engine.news_ingestion.urllib.request.urlopen"
    ) as urlopen, patch(
        "backend.engine.news_ingestion.feedparser.parse",
        side_effect=feeds,
    ) as parse:
        urlopen.return_value.__enter__.return_value = object()
        first = ingestor.get_latest_news("Test Location", "rail")
        repeated = ingestor.get_latest_news("Test Location", "rail")
        expired = ingestor.get_latest_news("Test Location", "rail")

    assert first == repeated == "Cached headline"
    assert expired == "Fresh headline"
    assert parse.call_count == 2


def test_rss_response_uses_first_three_headlines_with_separator():
    ingestor = DynamicNewsIngestor()
    feed = SimpleNamespace(
        entries=[SimpleNamespace(title=f"Headline {index}") for index in range(1, 6)]
    )

    with patch("backend.engine.news_ingestion.urllib.request.urlopen") as urlopen, patch(
        "backend.engine.news_ingestion.feedparser.parse",
        return_value=feed,
    ):
        urlopen.return_value.__enter__.return_value = object()
        result = ingestor.get_latest_news("Test Location", "sea")

    assert result == "Headline 1 | Headline 2 | Headline 3"


def test_successful_rss_response_matches_string_caller_contract():
    ingestor = DynamicNewsIngestor()
    feed = SimpleNamespace(
        entries=[
            SimpleNamespace(title="Port congestion reported"),
            SimpleNamespace(title="Berthing delays expected"),
            SimpleNamespace(title="Cargo schedules adjusted"),
        ]
    )

    with patch("backend.engine.news_ingestion.urllib.request.urlopen") as urlopen, patch(
        "backend.engine.news_ingestion.feedparser.parse",
        return_value=feed,
    ):
        urlopen.return_value.__enter__.return_value = object()
        result = ingestor.get_latest_news("Test Location", "sea")

    assert isinstance(result, str)
    assert result == (
        "Port congestion reported | Berthing delays expected | Cargo schedules adjusted"
    )