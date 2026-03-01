"""
Conversation Memory using SQLite
Stores conversation history and thought traces
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Optional
from pathlib import Path


class ConversationMemory:
    """SQLite-backed conversation memory"""
    
    def __init__(self, db_path: str = "dexter_ai.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                task TEXT,
                status TEXT DEFAULT 'running',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create thoughts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS thoughts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                node TEXT NOT NULL,
                thought TEXT,
                reasoning TEXT,
                action TEXT,
                action_input TEXT,
                observation TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)
        
        # Create messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)
        
        # Create tool_results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                command TEXT,
                result TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def create_session(self, session_id: str, target: str, task: str) -> bool:
        """Create a new session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO sessions (session_id, target, task, status)
                VALUES (?, ?, ?, 'running')
            """, (session_id, target, task))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def update_session_status(self, session_id: str, status: str):
        """Update session status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE sessions 
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE session_id = ?
        """, (status, session_id))
        
        conn.commit()
        conn.close()
    
    def add_thought(self, session_id: str, thought: dict):
        """Add a thought to the session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO thoughts (session_id, node, thought, reasoning, action, action_input, observation, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            thought.get("node", ""),
            thought.get("thought", ""),
            thought.get("reasoning", ""),
            thought.get("action", ""),
            json.dumps(thought.get("action_input", {})),
            thought.get("observation", ""),
            thought.get("timestamp", datetime.now().isoformat())
        ))
        
        conn.commit()
        conn.close()
    
    def add_message(self, session_id: str, role: str, content: str):
        """Add a message to the session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO messages (session_id, role, content)
            VALUES (?, ?, ?)
        """, (session_id, role, content))
        
        conn.commit()
        conn.close()
    
    def add_tool_result(self, session_id: str, tool_name: str, command: str, result: dict):
        """Add a tool result to the session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO tool_results (session_id, tool_name, command, result)
            VALUES (?, ?, ?, ?)
        """, (session_id, tool_name, command, json.dumps(result)))
        
        conn.commit()
        conn.close()
    
    def get_thoughts(self, session_id: str) -> list[dict]:
        """Get all thoughts for a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT node, thought, reasoning, action, action_input, observation, timestamp
            FROM thoughts
            WHERE session_id = ?
            ORDER BY id ASC
        """, (session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        thoughts = []
        for row in rows:
            thoughts.append({
                "node": row[0],
                "thought": row[1],
                "reasoning": row[2],
                "action": row[3],
                "action_input": json.loads(row[4]) if row[4] else {},
                "observation": row[5],
                "timestamp": row[6]
            })
        
        return thoughts
    
    def get_session(self, session_id: str) -> Optional[dict]:
        """Get session details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT session_id, target, task, status, created_at, updated_at
            FROM sessions
            WHERE session_id = ?
        """, (session_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "session_id": row[0],
                "target": row[1],
                "task": row[2],
                "status": row[3],
                "created_at": row[4],
                "updated_at": row[5]
            }
        
        return None
    
    def list_sessions(self, limit: int = 10) -> list[dict]:
        """List recent sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT session_id, target, task, status, created_at, updated_at
            FROM sessions
            ORDER BY updated_at DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            sessions.append({
                "session_id": row[0],
                "target": row[1],
                "task": row[2],
                "status": row[3],
                "created_at": row[4],
                "updated_at": row[5]
            })
        
        return sessions


# Singleton instance
memory = ConversationMemory()
