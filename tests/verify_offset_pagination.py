import sys
import unittest
from unittest.mock import MagicMock, ANY
from datetime import datetime, timezone

# Add current directory to path so we can import main
sys.path.append(".")

# Mock validation/dependencies to avoid dragging in the whole world
# We need to mock things BEFORE importing main if main executes code at top level that fails
# But main.py looks mostly safe (definitions).

import os

# Mock Environment Variables needed for Config/Models
os.environ["REFRESH_TOKEN_HASH_KEY"] = "dummy_key_for_testing"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "7"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

from models import Clipboard, User
from schemas import ClipboardSyncResponse

# We need to mock get_clipboard_sync dependencies
# It requires: offset, limit, include_deleted, db, current_user

class TestOffsetPagination(unittest.TestCase):
    def setUp(self):
        # We need to import the function to test
        # To avoid running startup logic, we just import what we need
        # But get_clipboard_sync is in main.py.
        from main import get_clipboard_sync
        self.get_clipboard_sync = get_clipboard_sync

    def test_pagination_logic(self):
        # Mock DB Session
        mock_db = MagicMock()
        mock_query = mock_db.query.return_value
        mock_filter_user = mock_query.filter_by.return_value
        
        # Test Case 1: Initial fetch (offset 0)
        # Setup mock data associated with the user
        # We expect filter(Clipboard.is_deleted == False) (default)
        # Then filter(Clipboard.index > 0)
        # Then order_by(Clipboard.index.asc())
        # Then limit(50)
        
        # The chain in the code is:
        # query = db.query(Clipboard).filter_by(user_id=uid)
        # if not include_deleted: query = query.filter(is_deleted == False)
        # entries = query.filter(index > offset).order_by(index.asc()).limit(limit).all()
        
        # Let's mock the chain effectively
        # It's a bit complex to mock chained calls perfectly with SQLAlchemy syntax 
        # because filter returns a query, order_by returns a query...
        
        # Simpler approach: Create a fake chain
        mock_step1 = MagicMock() # filter_by(user_id)
        mock_step2 = MagicMock() # filter(is_deleted==False)
        mock_step3 = MagicMock() # filter(index > offset)
        mock_step4 = MagicMock() # order_by
        mock_step5 = MagicMock() # limit
        
        mock_db.query.return_value.filter_by.return_value = mock_step1
        mock_step1.filter.return_value = mock_step2
        mock_step2.filter.return_value = mock_step3
        mock_step3.order_by.return_value = mock_step4
        mock_step4.limit.return_value = mock_step5
        
        # Make some dummy entries
        entry1 = Clipboard(
            id="uuid-1", 
            index=10, 
            ciphertext=b"data1", 
            nonce=b"nonce1", 
            blob_version=1, 
            timestamp=datetime.now(timezone.utc),
            is_deleted=False
        )
        entry2 = Clipboard(
            id="uuid-2", 
            index=15, 
            ciphertext=b"data2", 
            nonce=b"nonce2", 
            blob_version=1, 
            timestamp=datetime.now(timezone.utc),
            is_deleted=False
        )
        
        mock_step5.all.return_value = [entry1, entry2]
        
        # Mock Count
        mock_step1.count.return_value = 100 
        # Note: Code calls query.count() which is 'query' variable.
        # Logic analysis:
        # query = db.query(...) .filter_by(...)
        # if not include_deleted: query = query.filter(...)
        # ...
        # total_count = query.count()
        # So it uses 'query' right before pagination filters (offset/limit).
        
        # Since our mock structure might be brittle vs actual code flow, 
        # let's just verifying the result processing logic assuming DB returns the list.
        
        
        mock_user = User(id=1, email="test@test.com")
        
        # Run Function
        response = self.get_clipboard_sync(
            offset=0,
            limit=50, 
            include_deleted=False,
            db=mock_db,
            current_user=mock_user
        )
        
        # Assertions
        print("Response Entries:", len(response["entries"]))
        self.assertEqual(len(response["entries"]), 2)
        self.assertEqual(response["next_offset"], 15) # Should match highest index
        self.assertEqual(response["entries"][0]["id"], "uuid-1")
        self.assertEqual(response["entries"][1]["id"], "uuid-2")
        
        print("Success: Initial fetch returned correct next_offset")

    def test_empty_result(self):
        from main import get_clipboard_sync
        
        mock_db = MagicMock()
        # Mock returning empty list
        mock_db.query.return_value.filter_by.return_value.filter.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value.filter_by.return_value.count.return_value = 0
        
        mock_user = User(id=1)
        
        response = get_clipboard_sync(
            offset=100,
            limit=50,
            include_deleted=False, 
            db=mock_db,
            current_user=mock_user
        )
        
        self.assertEqual(len(response["entries"]), 0)
        self.assertEqual(response["next_offset"], 100) # Should remain same as input offset
        self.assertFalse(response["has_more"])
        print("Success: Empty result handled correctly")

if __name__ == '__main__':
    unittest.main()
