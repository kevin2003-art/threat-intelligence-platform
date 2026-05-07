import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enforcer'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'database'))

from elasticsearch import Elasticsearch
from block_logger import get_recent_logs
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

ES_HOST = "http://localhost:9200"
BLOCK_INDEX = "block-logs"


def get_es():
    es = Elasticsearch([ES_HOST])
    if not es.ping():
        raise ConnectionError("Cannot connect to Elasticsearch")
    return es


def create_block_index(es):
    if es.indices.exists(index=BLOCK_INDEX):
        print(f"[ES] Index '{BLOCK_INDEX}' already exists")
        return

    mapping = {
        "mappings": {
            "properties": {
                "ip":         {"type": "keyword"},
                "action":     {"type": "keyword"},
                "success":    {"type": "boolean"},
                "severity":   {"type": "keyword"},
                "source":     {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "message":    {"type": "text"},
                "timestamp":  {
                    "type": "date",
                    "format": "strict_date_optional_time||epoch_millis"
                }
            }
        }
    }
    es.indices.create(index=BLOCK_INDEX, body=mapping)
    print(f"[ES] Created index: {BLOCK_INDEX}")


def index_block_logs():
    es = get_es()
    create_block_index(es)

    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = MongoClient(mongo_uri)
    db = client["threat_intelligence"]
    logs = list(db["block_logs"].find({}))

    print(f"[ES] Indexing {len(logs)} block log entries...")
    ok, fail = 0, 0

    for log in logs:
        doc_id = str(log.pop("_id"))
        try:
            es.index(index=BLOCK_INDEX, id=doc_id, document=log)
            ok += 1
        except Exception as e:
            print(f"[ES ERROR] {e}")
            fail += 1

    es.indices.refresh(index=BLOCK_INDEX)
    total = es.count(index=BLOCK_INDEX)["count"]
    print(f"[ES] Done — Indexed: {ok} | Failed: {fail} | Total: {total}")


if __name__ == "__main__":
    index_block_logs()
