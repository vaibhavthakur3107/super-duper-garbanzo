"""
Cyber-Sentry API
FastAPI backend for the Red Team Cyber-Sentry AI Agent System
"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from ..agents import AgentOrchestrator, AgentState, Thought
from ..agents.specialized import AgentFactory
from ..tools.registry import ToolRegistry
from ..guardrails.security import SecurityGuardrails


# Pydantic models
class TaskRequest(BaseModel):
    task: str = Field(..., description="Task description for the agent")
    target: Optional[str] = Field(None, description="Target URL or IP address")
    agents: Optional[list[str]] = Field(None, description="Specific agents to use")
    options: dict = Field(default_factory=dict, description="Additional options")


class TaskResponse(BaseModel):
    session_id: str
    status: str
    task: str
    start_time: str
    results: list


class AgentStatus(BaseModel):
    name: str
    state: str
    last_thought: Optional[dict] = None


class SystemStatus(BaseModel):
    status: str
    active_sessions: int
    registered_agents: list[str]
    available_tools: list[dict]
    guardrails: list[dict]


class ThoughtTraceEvent(BaseModel):
    type: str = "thought_trace"
    agent: str
    thought: dict
    timestamp: str


# Global state
tool_registry: ToolRegistry
guardrails: SecurityGuardrails
orchestrator: AgentOrchestrator
active_connections: dict[str, WebSocket]


async def startup_event():
    """Initialize the system on startup"""
    global tool_registry, guardrails, orchestrator, active_connections
    
    # Initialize components
    tool_registry = ToolRegistry()
    guardrails = SecurityGuardrails(allowed_domains=["example.com", "test.local"])
    orchestrator = AgentOrchestrator()
    active_connections = {}
    
    # Register agents
    factory = AgentFactory(tool_registry, guardrails.guardrails)
    for agent in factory.create_all_agents():
        orchestrator.register_agent(agent)
    
    print("Cyber-Sentry AI System initialized")
    print(f"Registered agents: {orchestrator.list_agents()}")
    print(f"Available tools: {len(tool_registry.list_tools())}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    await startup_event()
    yield
    # Cleanup


# Create FastAPI app
app = FastAPI(
    title="Cyber-Sentry AI",
    description="Red Team Cyber-Sentry AI Agent System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Routes
@app.get("/", response_model=dict)
async def root():
    return {
        "name": "Cyber-Sentry AI",
        "version": "1.0.0",
        "description": "Red Team Cyber-Sentry AI Agent System",
        "status": "operational"
    }


@app.get("/status", response_model=SystemStatus)
async def get_status():
    """Get system status"""
    return SystemStatus(
        status="operational",
        active_sessions=len(orchestrator.active_sessions),
        registered_agents=orchestrator.list_agents(),
        available_tools=tool_registry.list_tools(),
        guardrails=guardrails.list_guardrails()
    )


@app.post("/tasks", response_model=TaskResponse)
async def create_task(request: TaskRequest):
    """Execute a new task using the agent system"""
    session_id = str(uuid.uuid4())
    
    # Build the task prompt
    task = request.task
    if request.target:
        task = f"{task} Target: {request.target}"
    
    # Execute the task
    session = await orchestrator.execute_task(task, request.agents)
    
    return TaskResponse(
        session_id=session["id"],
        status="completed",
        task=session["task"],
        start_time=session["start_time"],
        results=session["results"]
    )


@app.get("/tasks/{session_id}")
async def get_task(session_id: str):
    """Get task results by session ID"""
    session = orchestrator.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.get("/tasks")
async def list_tasks():
    """List all sessions"""
    return {
        "sessions": [
            {
                "id": sid,
                "task": s["task"],
                "start_time": s["start_time"],
                "end_time": s.get("end_time")
            }
            for sid, s in orchestrator.active_sessions.items()
        ]
    }


@app.get("/agents")
async def list_agents():
    """List all registered agents"""
    return {
        "agents": orchestrator.list_agents()
    }


@app.get("/agents/{agent_name}/thoughts")
async def get_agent_thoughts(agent_name: str):
    """Get thought trace for a specific agent"""
    agent = orchestrator.agents.get(agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent": agent_name,
        "thoughts": agent.get_thought_trace()
    }


@app.get("/tools")
async def list_tools():
    """List all available tools"""
    return {
        "tools": tool_registry.list_tools()
    }


@app.get("/guardrails")
async def list_guardrails():
    """List all security guardrails"""
    return {
        "guardrails": guardrails.list_guardrails()
    }


@app.websocket("/ws/thoughts")
async def websocket_thoughts(websocket: WebSocket):
    """WebSocket endpoint for real-time thought trace streaming"""
    await websocket.accept()
    client_id = str(uuid.uuid4())
    active_connections[client_id] = websocket
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat()
        })
        
        # Keep connection alive and relay messages
        while True:
            data = await websocket.receive_text()
            # Echo back for demonstration - in production, 
            # this would be connected to agent thought streams
            await websocket.send_json({
                "type": "echo",
                "data": data,
                "timestamp": datetime.now().isoformat()
            })
            
    except WebSocketDisconnect:
        del active_connections[client_id]
    except Exception as e:
        if client_id in active_connections:
            del active_connections[client_id]
        await websocket.close()


async def broadcast_thought(thought: Thought):
    """Broadcast a thought to all connected WebSocket clients"""
    for client_id, ws in active_connections.items():
        try:
            await ws.send_json({
                "type": "thought_trace",
                "agent": thought.agent,
                "thought": thought.to_dict(),
                "timestamp": datetime.now().isoformat()
            })
        except:
            pass


@app.get("/events/thoughts/{session_id}")
async def thought_events(session_id: str):
    """Server-Sent Events endpoint for thought trace streaming"""
    session = orchestrator.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    async def event_generator():
        # Yield existing thoughts
        for agent_name, thoughts in session.get("thought_traces", {}).items():
            for thought in thoughts:
                yield {
                    "event": "thought",
                    "data": str(thought)
                }
        
        # In production, this would stream new thoughts as they happen
        yield {
            "event": "done",
            "data": "Session complete"
        }
    
    return EventSourceResponse(event_generator())


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    components: dict


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        components={
            "orchestrator": "operational",
            "tool_registry": "operational",
            "guardrails": "operational"
        }
    )


# Run with: uvicorn cyber_sentry.api.main:app --reload
