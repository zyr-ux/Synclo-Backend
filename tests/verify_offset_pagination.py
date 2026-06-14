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

from app.models.models import Clipboard, User
from app.schemas.schemas import ClipboardSyncResponse

# We need to mock get_clipboard_sync dependencies
# It requires: offset, limit, include_deleted, db, current_user

class TestOffsetPagination(unittest.TestCase):
    def setUp(self):
        # We need to import the function to test
        # To avoid running startup logic, we just import what we need
        # But get_clipboard_sync is in main.py.
        from app.endpoints.clipboard_endpoints import get_sync_clipboard
        self.get_clipboard_sync = get_sync_clipboard

    def test_pagination_logic(self):
        # Mock DB Session
        mock_db = MagicMock()
        mock_query = mock_db.query.return_value
        
        # Simpler approach: Create a fake chain
        mock_step1 = MagicMock() # order_by
        mock_step2 = MagicMock() # offset
        mock_step3 = MagicMock() # limit
        
        mock_db.query.return_value.filter.return_value = mock_step1
        mock_step1.order_by.return_value = mock_step2
        mock_step2.offset.return_value = mock_step3
        
        # Make some dummy entries
        entry1 = Clipboard(
            id="uuid-1", 
            ciphertext=b"data1", 
            nonce=b"nonce1", 
            blob_version=1, 
            timestamp=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_deleted=False
        )
        entry2 = Clipboard(
            id="uuid-2", 
            ciphertext=b"data2", 
            nonce=b"nonce2", 
            blob_version=1, 
            timestamp=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_deleted=False
        )
        
        mock_step3.limit.return_value.all.return_value = [entry1, entry2]
        
        mock_user = User(id=1, email="test@test.com")
        
        # Run Function
        response = self.get_clipboard_sync(
            since=None,
            offset=0,
            limit=50,
            db=mock_db,
            current_user=mock_user
        )
        
        # Assertions
        print("Response Entries:", len(response["entries"]))
        self.assertEqual(len(response["entries"]), 2)
        self.assertEqual(response["next_offset"], 2) # Should match offset + len(entries)
        self.assertEqual(response["entries"][0]["id"], "uuid-1")
        self.assertEqual(response["entries"][1]["id"], "uuid-2")
        
        print("Success: Initial fetch returned correct next_offset")

    def test_empty_result(self):
        from app.endpoints.clipboard_endpoints import get_sync_clipboard
        
        mock_db = MagicMock()
        # Mock returning empty list
        mock_db.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
        
        mock_user = User(id=1)
        
        response = get_sync_clipboard(
            since=None,
            offset=100,
            limit=50,
            db=mock_db,
            current_user=mock_user
        )
        
        self.assertEqual(len(response["entries"]), 0)
        self.assertEqual(response["next_offset"], 100) # Should remain same as input offset
        self.assertFalse(response["has_more"])
        print("Success: Empty result handled correctly")

if __name__ == '__main__':
    unittest.main()
