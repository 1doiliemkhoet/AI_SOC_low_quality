"""
RAG Service Integration Tests
AI-Augmented SOC

Run inside the rag-service container:
    python -m pytest /app/test_rag_service.py -q

These tests cover the production RAG API plus direct VectorStore operations.
They intentionally avoid mutating the populated production collections.
"""

import os
from uuid import uuid4

import httpx
import pytest

from embeddings import EmbeddingEngine
from vector_store import VectorStore


RAG_BASE_URL = os.getenv("RAG_TEST_BASE_URL", "http://localhost:8000")
CHROMA_HOST = os.getenv("RAG_TEST_CHROMA_HOST", "chromadb")
CHROMA_PORT = int(os.getenv("RAG_TEST_CHROMA_PORT", "8000"))


@pytest.fixture(scope="module")
def embedding_engine():
    return EmbeddingEngine()


@pytest.fixture(scope="module")
def vector_store(embedding_engine):
    return VectorStore(
        embedding_engine,
        host=CHROMA_HOST,
        port=CHROMA_PORT,
    )


@pytest.fixture
async def client():
    async with httpx.AsyncClient(base_url=RAG_BASE_URL, timeout=60.0) as client:
        yield client


def assert_api_success(response: httpx.Response):
    assert response.status_code == 200, (
        f"Expected HTTP 200, got {response.status_code}: {response.text}"
    )


@pytest.mark.asyncio
async def test_embedding_engine(embedding_engine):
    embedding = embedding_engine.embed_text(
        "SSH brute force attack from external IP"
    )
    assert len(embedding) == 384

    batch = embedding_engine.embed_batch(
        [
            "Malware detected on endpoint",
            "Suspicious network traffic",
            "Failed login attempts",
        ]
    )
    assert batch.shape == (3, 384)

    similarity = embedding_engine.compute_similarity(
        "SSH brute force attack",
        "Multiple failed SSH login attempts",
    )
    assert similarity > 0.5


def test_vector_store_connection(vector_store):
    assert vector_store.is_connected(), (
        f"ChromaDB connection failed for {CHROMA_HOST}:{CHROMA_PORT}"
    )


@pytest.mark.asyncio
async def test_vector_store_semantic_search(vector_store):
    collection_name = f"rag-test-{uuid4().hex[:8]}"
    assert vector_store.create_collection(collection_name)

    documents = [
        "T1110 Brute Force: Adversaries may use brute force techniques.",
        "T1021 Remote Services: Adversaries may use remote services.",
        "T1078 Valid Accounts: Adversaries may abuse existing accounts.",
    ]
    metadatas = [
        {"technique_id": "T1110", "type": "test"},
        {"technique_id": "T1021", "type": "test"},
        {"technique_id": "T1078", "type": "test"},
    ]

    try:
        assert await vector_store.add_documents(
            collection_name=collection_name,
            documents=documents,
            metadatas=metadatas,
            ids=["T1110", "T1021", "T1078"],
        )

        results = await vector_store.query(
            collection_name=collection_name,
            query_text="SSH brute force attack",
            top_k=2,
            min_similarity=0.0,
        )
        assert results
        assert results[0]["metadata"]["technique_id"] == "T1110"

        stats = vector_store.get_collection_stats(collection_name)
        assert stats["count"] == 3
    finally:
        vector_store.delete_collection(collection_name)


@pytest.mark.asyncio
async def test_exact_metadata_lookup_cve(vector_store):
    results = await vector_store.get_by_metadata(
        collection_name="cve_database",
        metadata_filter={"cve_id": "CVE-2016-3082"},
        top_k=1,
    )
    assert len(results) == 1
    assert results[0]["metadata"]["cve_id"] == "CVE-2016-3082"
    assert results[0]["similarity_score"] == 1.0


@pytest.mark.asyncio
async def test_exact_metadata_lookup_mitre(vector_store):
    results = await vector_store.get_by_metadata(
        collection_name="mitre_attack",
        metadata_filter={"technique_id": "T1110.001"},
        top_k=1,
    )
    assert len(results) == 1
    assert results[0]["metadata"]["technique_id"] == "T1110.001"
    assert results[0]["similarity_score"] == 1.0


@pytest.mark.asyncio
async def test_api_exact_cve_and_semantic_dedup(client):
    response = await client.post(
        "/retrieve",
        json={
            "query": "CVE-2016-3082 Apache Struts remote code execution",
            "collection": "cve_database",
            "top_k": 3,
            "min_similarity": 0.5,
        },
    )
    assert_api_success(response)

    payload = response.json()
    assert payload["results"]
    assert payload["results"][0]["metadata"]["cve_id"] == "CVE-2016-3082"
    assert payload["results"][0]["similarity_score"] == 1.0

    cve_ids = [
        result["metadata"].get("cve_id")
        for result in payload["results"]
    ]
    assert len(cve_ids) == len(set(cve_ids))


@pytest.mark.asyncio
async def test_api_exact_mitre_auto_detection(client):
    response = await client.post(
        "/retrieve",
        json={
            "query": "T1110.001",
            "collection": "mitre_attack",
            "top_k": 3,
            "min_similarity": 0.95,
        },
    )
    assert_api_success(response)

    payload = response.json()
    assert payload["results"]
    assert payload["results"][0]["metadata"]["technique_id"] == "T1110.001"
    assert payload["results"][0]["similarity_score"] == 1.0


@pytest.mark.asyncio
async def test_api_runbook_semantic_retrieval(client):
    response = await client.post(
        "/retrieve",
        json={
            "query": "SSH brute force incident response block source IP",
            "collection": "security_runbooks",
            "top_k": 3,
            "min_similarity": 0.5,
        },
    )
    assert_api_success(response)

    payload = response.json()
    assert len(payload["results"]) >= 2
    sections = [r["metadata"].get("section") for r in payload["results"]]
    assert "Detection" in sections
    assert "Containment" in sections


@pytest.mark.asyncio
async def test_api_invalid_collection_returns_400(client):
    response = await client.post(
        "/retrieve",
        json={
            "query": "test",
            "collection": "invalid_collection",
            "top_k": 3,
            "min_similarity": 0.5,
        },
    )
    assert response.status_code == 400
    assert "Unsupported collection" in response.json()["detail"]


@pytest.mark.asyncio
async def test_api_health_reports_knowledge_base_readiness(client):
    response = await client.get("/health")
    assert_api_success(response)

    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["chromadb_connected"] is True
    assert payload["knowledge_base_ready"] is True

    counts = payload["knowledge_base"]
    assert counts["mitre_attack"] > 0
    assert counts["cve_database"] > 0
    assert counts["security_runbooks"] > 0
