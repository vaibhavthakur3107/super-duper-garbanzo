"""
Cyber-Sentry AI - Core Agent System
Multi-agent architecture with ReAct reasoning for red team operations
"""

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentState(Enum):
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    COMPLETED = "completed"
    ERROR = "error"
    BLOCKED = "blocked"


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Thought:
    """Represents a single thought in the reasoning chain"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    agent: str = ""
    thought: str = ""
    action: Optional[str] = None
    action_input: dict = field(default_factory=dict)
    observation: Optional[str] = None
    reasoning: str = ""
    confidence: float = 0.0
    state: AgentState = AgentState.IDLE

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "agent": self.agent,
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "state": self.state.value
        }


@dataclass
class AgentConfig:
    name: str
    description: str
    system_prompt: str
    max_iterations: int = 10
    timeout: int = 300
    tools: list = field(default_factory=list)
    guardrails: list = field(default_factory=list)


class Tool(ABC):
    """Base class for all tools available to agents"""
    
    def __init__(self, name: str, description: str, category: str = "general"):
        self.name = name
        self.description = description
        self.category = category
    
    @abstractmethod
    async def execute(self, **kwargs) -> dict:
        """Execute the tool with given parameters"""
        pass
    
    @abstractmethod
    def validate_input(self, **kwargs) -> tuple[bool, Optional[str]]:
        """Validate input parameters"""
        pass


@dataclass
class ToolResult:
    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "metadata": self.metadata
        }


class Guardrail(ABC):
    """Security guardrail base class"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    @abstractmethod
    async def check(self, action: str, params: dict, context: dict) -> tuple[bool, Optional[str]]:
        """
        Check if the action is allowed
        Returns: (allowed, reason_if_blocked)
        """
        pass


class Agent(ABC):
    """Base agent class with ReAct reasoning"""
    
    def __init__(self, config: AgentConfig, tool_registry: dict[str, Tool], guardrail_registry: list[Guardrail]):
        self.config = config
        self.tool_registry = tool_registry
        self.guardrail_registry = guardrail_registry
        self.thought_history: list[Thought] = []
        self.current_state = AgentState.IDLE
        self.context: dict = {}
        
    async def think(self, prompt: str) -> Thought:
        """Process a prompt using ReAct reasoning"""
        thought = Thought(
            agent=self.config.name,
            thought=prompt,
            state=AgentState.THINKING
        )
        
        # ReAct: Reason about the action
        thought.reasoning = await self._reason(prompt)
        
        # ReAct: Decide on action
        thought.action, thought.action_input = await self._decide_action(prompt)
        
        # Check guardrails before acting
        allowed, reason = await self._check_guardrails(thought.action, thought.action_input)
        if not allowed:
            thought.state = AgentState.BLOCKED
            thought.observation = f"Action blocked: {reason}"
            self.thought_history.append(thought)
            return thought
        
        # ReAct: Act
        thought.state = AgentState.ACTING
        self.thought_history.append(thought)
        
        if thought.action:
            observation = await self._act(thought.action, thought.action_input)
            thought.observation = observation
            thought.state = AgentState.OBSERVING
        
        return thought
    
    async def _reason(self, prompt: str) -> str:
        """Analyze the prompt and context to determine next steps"""
        return f"Analyzing request: {prompt[:100]}..."
    
    async def _decide_action(self, prompt: str) -> tuple[Optional[str], dict]:
        """Decide which action to take"""
        return None, {}
    
    async def _act(self, action: str, params: dict) -> str:
        """Execute the chosen action"""
        if action in self.tool_registry:
            tool = self.tool_registry[action]
            valid, error = tool.validate_input(**params)
            if not valid:
                return f"Validation error: {error}"
            
            result = await tool.execute(**params)
            return json.dumps(result.to_dict())
        return f"Unknown action: {action}"
    
    async def _check_guardrails(self, action: str, params: dict) -> tuple[bool, Optional[str]]:
        """Check all guardrails before executing action"""
        context = {
            "agent": self.config.name,
            "target": params.get("target", ""),
            "action": action
        }
        
        for guardrail in self.guardrail_registry:
            allowed, reason = await guardrail.check(action, params, context)
            if not allowed:
                logger.warning(f"Guardrail {guardrail.name} blocked: {reason}")
                return False, reason
        
        return True, None
    
    def get_thought_trace(self) -> list[dict]:
        """Get the full thought trace for visualization"""
        return [t.to_dict() for t in self.thought_history]
    
    def clear_history(self):
        """Clear thought history"""
        self.thought_history = []


class AgentOrchestrator:
    """Orchestrates multiple agents for complex operations"""
    
    def __init__(self):
        self.agents: dict[str, Agent] = {}
        self.active_sessions: dict[str, dict] = {}
        
    def register_agent(self, agent: Agent):
        self.agents[agent.config.name] = agent
        logger.info(f"Registered agent: {agent.config.name}")
    
    async def execute_task(self, task: str, agent_names: Optional[list[str]] = None) -> dict:
        """Execute a task using specified agents"""
        session_id = str(uuid.uuid4())
        session = {
            "id": session_id,
            "task": task,
            "start_time": datetime.now().isoformat(),
            "thought_traces": {},
            "results": []
        }
        self.active_sessions[session_id] = session
        
        target_agents = [self.agents[name] for name in (agent_names or self.agents.keys())]
        
        for agent in target_agents:
            thought = await agent.think(task)
            session["thought_traces"][agent.config.name] = agent.get_thought_trace()
            session["results"].append(thought.to_dict())
        
        session["end_time"] = datetime.now().isoformat()
        return session
    
    def get_session(self, session_id: str) -> Optional[dict]:
        return self.active_sessions.get(session_id)
    
    def list_agents(self) -> list[str]:
        return list(self.agents.keys())
