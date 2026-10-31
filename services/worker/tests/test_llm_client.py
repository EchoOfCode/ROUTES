"""Unit tests for the generic LLMClient (S6): live/record/replay cache
modes, against a fake HTTP transport - no real network calls."""

import httpx
import pytest

from worker.llm.client import LLMClient, LLMError


def _transport(content: str, record: list | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
    return httpx.MockTransport(handler)


def test_live_mode_calls_out_and_never_touches_the_cache(tmp_path):
    client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m", cache_mode="live",
                       cache_dir=str(tmp_path), transport=_transport("hi"))
    out = client.complete([{"role": "user", "content": "hello"}])
    assert out == "hi"
    assert list(tmp_path.iterdir()) == []


def test_record_mode_calls_out_and_saves_to_the_cache(tmp_path):
    client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m", cache_mode="record",
                       cache_dir=str(tmp_path), transport=_transport("hi"))
    out = client.complete([{"role": "user", "content": "hello"}])
    assert out == "hi"
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_replay_mode_never_calls_out_and_errors_on_a_cache_miss(tmp_path):
    calls: list = []
    client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m", cache_mode="replay",
                       cache_dir=str(tmp_path), transport=_transport("should not be used", record=calls))
    with pytest.raises(LLMError):
        client.complete([{"role": "user", "content": "hello"}])
    assert calls == []


def test_replay_mode_reads_a_previously_recorded_response(tmp_path):
    record_client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m",
                              cache_mode="record", cache_dir=str(tmp_path), transport=_transport("recorded value"))
    record_client.complete([{"role": "user", "content": "hello"}])

    calls: list = []
    replay_client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m",
                              cache_mode="replay", cache_dir=str(tmp_path),
                              transport=_transport("should not be used", record=calls))
    out = replay_client.complete([{"role": "user", "content": "hello"}])
    assert out == "recorded value"
    assert calls == []


def test_different_messages_get_different_cache_keys(tmp_path):
    client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m", cache_mode="record",
                       cache_dir=str(tmp_path), transport=_transport("hi"))
    client.complete([{"role": "user", "content": "hello"}])
    client.complete([{"role": "user", "content": "goodbye"}])
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_non_200_response_raises_llm_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")
    client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m",
                       transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError):
        client.complete([{"role": "user", "content": "hello"}])


def test_malformed_response_shape_raises_llm_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})
    client = LLMClient(endpoint="http://fake/v1/chat/completions", api_key="k", model="m",
                       transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError):
        client.complete([{"role": "user", "content": "hello"}])


def test_missing_endpoint_or_model_raises_immediately():
    with pytest.raises(LLMError):
        LLMClient(endpoint="", api_key="k", model="m")
    with pytest.raises(LLMError):
        LLMClient(endpoint="http://fake", api_key="k", model="")


def test_unknown_cache_mode_raises_immediately():
    with pytest.raises(LLMError):
        LLMClient(endpoint="http://fake", api_key="k", model="m", cache_mode="sometimes")
