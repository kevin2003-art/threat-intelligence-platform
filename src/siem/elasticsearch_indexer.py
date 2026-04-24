from elasticsearch import Elasticsearch
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(_file_), '..', 'database'))
from mongo_handler import get_collection

ES_HOST = "http://localhost:9200"
INDEX_NAME = "threat-indicators"


def get_es_client():
    """Connect to Elasticsearch."""
    es = Elasticsearch([ES_HOST])
    if not es.ping():
        raise ConnectionError(
            f"Cannot connect to Elasticsearch at {ES_HOST}\n"
            "Make sure it is running: sudo systemctl start elasticsearch"
        )
    print(f"[ES] Connected to Elasticsearch at {ES_HOST}")
    return es


def create_index(es):
    """Create the index with proper field mappings."""
    if es.indices.exists(index=INDEX_NAME):
        print(f"[ES] Index '{INDEX_NAME}' already exists — skipping creation")
        return

    mapping = {
        "mappings": {
            "properties": {
                "type":             {"type": "keyword"},
                "value":            {"type": "keyword"},
                "source":           {"type": "keyword"},
                "risk_score":       {"type": "integer"},
                "severity":         {"type": "keyword"},
                "country":          {"type": "keyword"},
                "tags":             {"type": "keyword"},
                "pulse_name":       {"type": "text"},
                "description":      {"type": "text"},
                "ingested_at":      {
                    "type": "date",
                    "format": "strict_date_optional_time||epoch_millis"
                },
                "scored_at":        {
                    "type": "date",
                    "format": "strict_date_optional_time||epoch_millis"
                },
                "raw_score":        {"type": "float"},
                "abuse_confidence": {"type": "integer"},
                "malicious_votes":  {"type": "integer"},
                "total_engines":    {"type": "integer"},
                "total_reports":    {"type": "integer"},
                "as_owner":         {"type": "keyword"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }

    es.indices.create(index=INDEX_NAME, body=mapping)
    print(f"[ES] Created index: {INDEX_NAME}")


def index_all_indicators():
    """Push all scored indicators from MongoDB into Elasticsearch."""
    es = get_es_client()
    create_index(es)

    collection = get_collection()
    indicators = list(collection.find({"risk_score": {"$exists": True}}))

    if not indicators:
        print("[ES] No scored indicators found. Run risk_scorer.py first.")
        return

    print(f"[ES] Indexing {len(indicators)} indicators...")
    ok, fail = 0, 0

    for ind in indicators:
        doc_id = str(ind.pop("_id"))
        try:
            es.index(index=INDEX_NAME, id=doc_id, document=ind)
            ok += 1
        except Exception as e:
            print(f"[ES ERROR] {e}")
            fail += 1

    es.indices.refresh(index=INDEX_NAME)
    total = es.count(index=INDEX_NAME)["count"]
    print(f"[ES] Indexed: {ok} | Failed: {fail} | Total in ES: {total}")


def show_critical_threats():
    """Print the top 10 most dangerous indicators."""
    es = get_es_client()
    result = es.search(
        index=INDEX_NAME,
        body={
            "query": {
                "bool": {
                    "should": [
                        {"term": {"severity": "CRITICAL"}},
                        {"term": {"severity": "HIGH"}}
                    ]
                }
            },
            "sort": [{"risk_score": {"order": "desc"}}],
            "size": 10
        }
    )
    hits = result["hits"]["hits"]
    print(f"\n[ES] Top threats ({len(hits)} results):")
    print(f"  {'IP/Domain':<25} {'Score':>5}  {'Severity':<10}  {'Source':<15}  Country")
    print("  " + "-" * 80)
    for h in hits:
        s = h["_source"]
        print(f"  {s.get('value','?'):<25} {s.get('risk_score',0):>5}  {s.get('severity','?'):<10}  {s.get('source','?'):<15}  {s.get('country','?')}")


if _name_ == "_main_":
    index_all_indicators()
    show_critical_threats()
