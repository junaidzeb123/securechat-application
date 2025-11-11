"""Append-only transcript + TranscriptHash helpers.""" 

import hashlib
import json
from typing import List, Dict, Any

class Transcript:
    def __init__(self):
        self.entries: List[str] = []

    def append(self, entry: Dict[str, Any]):
        self.entries.append(json.dumps(entry))

    def get_transcript(self) -> List[str]:
        return self.entries

    def transcript_hash(self) -> str:
        # Hash of all entries concatenated
        data = ''.join(self.entries).encode()
        return hashlib.sha256(data).hexdigest()
