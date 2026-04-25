from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "threat_intelligence"
COLLECTION_NAME = "indicators"


def get_collection():
    """Connect to MongoDB and return the indicators collection."""
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    # Unique index prevents duplicate entries
    collection.create_index(
        [("value", ASCENDING), ("source", ASCENDING)],
        unique=True
    )
    return collection


def insert_indicator(indicator: dict) -> bool:
    """Insert one indicator. Returns True if new, False if duplicate."""
    collection = get_collection()
    indicator["ingested_at"] = datetime.utcnow().isoformat()
    indicator["processed"] = False
    try:
        collection.insert_one(indicator)
        return True
    except DuplicateKeyError:
        return False


def insert_many_indicators(indicators: list) -> dict:
    """Bulk insert, skipping duplicates. Returns counts."""
    inserted, skipped = 0, 0
    for indicator in indicators:
        if insert_indicator(indicator):
            inserted += 1
        else:
            skipped += 1
    return {"inserted": inserted, "skipped_duplicates": skipped}


def get_all_indicators(limit=1000):
    """Get all indicators from database."""
    collection = get_collection()
    return list(collection.find({}, {"_id": 0}).limit(limit))


def get_scored_indicators(min_score=0):
    """Get indicators that have been scored."""
    collection = get_collection()
    return list(collection.find(
        {"risk_score": {"$exists": True, "$gte": min_score}},
        {"_id": 0}
    ))


def count_by_source():
    """Count indicators grouped by source."""
    collection = get_collection()
    pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    return list(collection.aggregate(pipeline))


def count_total():
    """Return total number of indicators."""
    return get_collection().count_documents({})


def clear_all():
    """Delete everything — use only for testing."""
    get_collection().delete_many({})
    print("[MongoDB] All indicators deleted")


if __name__ == "__main__":
    print(f"[MongoDB] Total indicators: {count_total()}")
    print("[MongoDB] By source:")
    for entry in count_by_source():
        print(f"  {entry['_id']}: {entry['count']}")
