"""
Cyber-Sentry AI - LangGraph Core Application
Multi-agent pentesting system with local LLM inference via Ollama
"""

import os
import json
import subprocess
import sqlite3
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TypedDict, Annotated, Sequence
from pathlib import Path

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool
from langchain_core.utils.function_calling import convert_to_openai_function

# Tool definitions
from .tools.network_tools import (
    nmap_scan, nikto_scan, whois_lookup, dig_lookup, 
    gobuster_scan, nuclei_scan, sqlmap_scan
)

# Prompts
from .prompts.system_prompt import (
    SYSTEM_PROMPT, SUPERVISOR_PROMPT, REFLECTION_PROMPT
)

# Guardrails
from .guardrails.scope_validator import validate_scope

# Database
from .db.memory import ConversationMemory


# ============================================================================
# State Definition
# ============================================================================

class AgentState(TypedDict):
    """State for the LangGraph agent"""
    messages: Sequence[BaseMessage]
    target: str
    task: str
    plan: list[str]
    current_step: str
    tool_calls: list[dict]
    tool_results: list[dict]
    thought_trace: list[dict]
    authorization_status: str
    reflection_notes: str
    iterations: int
    max_iterations: int
    error: str | None


# ============================================================================
# LLM Setup (Ollama)
# ============================================================================

def get_llm(model: str = "llama3", temperature: float = 0.7):
    """Initialize Ollama LLM"""
    return ChatOllama(
        model=model,
        base_url="http://localhost:11434",
        temperature=temperature,
        streaming=True,
    )


# ============================================================================
# Node Functions
# ============================================================================

def create_supervisor_node(llm):
    """Supervisor node - decides high-level plan"""
    
    def supervisor_node(state: AgentState) -> AgentState:
        target = state.get("target", "")
        task = state.get("task", "")
        
        if not target:
            state["error"] = "No target specified"
            return state
        
        # Check authorization
        if not validate_scope(target):
            state["authorization_status"] = "DENIED"
            state["error"] = f"Target {target} not in authorized scope"
            return state
        
        state["authorization_status"] = "AUTHORIZED"
        
        # Generate plan using LLM
        messages = [
            SystemMessage(content=SUPERVISOR_PROMPT.format(target=target, task=task))
        ]
        
        try:
            response = llm.invoke(messages)
            plan_text = response.content
            
            # Parse plan into steps
            plan = [s.strip() for s in plan_text.split("\n") if s.strip()]
            state["plan"] = plan
            state["current_step"] = plan[0] if plan else "reconnaissance"
            
            # Add to thought trace
            state["thought_trace"].append({
                "node": "supervisor",
                "thought": f"Analyzing target {target} and creating attack plan",
                "reasoning": f"Generated plan with {len(plan)} steps",
                "action": "plan_generation",
                "observation": f"Plan: {', '.join(plan[:3])}...",
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            # Fallback to default plan
            state["plan"] = ["reconnaissance", "vulnerability_scan", "exploitation"]
            state["current_step"] = "reconnaissance"
            state["error"] = str(e)
        
        return state
    
    return supervisor_node


def create_planner_node(llm):
    """Planner node - generates specific commands based on current step"""
    
    def planner_node(state: AgentState) -> AgentState:
        current_step = state.get("current_step", "")
        target = state.get("target", "")
        
        # Generate dynamic command based on step and target
        messages = [
            SystemMessage(content=f"""Generate the appropriate nmap/command for: {current_step}
Target: {target}
Return ONLY the command without explanation.""")
        ]
        
        try:
            response = llm.invoke(messages)
            command = response.content.strip()
            
            # Determine tool to use
            tool_name = "nmap_scan"  # default
            if "nikto" in current_step.lower():
                tool_name = "nikto_scan"
            elif "whois" in current_step.lower():
                tool_name = "whois_lookup"
            elif "dig" in current_step.lower() or "dns" in current_step.lower():
                tool_name = "dig_lookup"
            elif "gobuster" in current_step.lower() or "directory" in current_step.lower():
                tool_name = "gobuster_scan"
            elif "nuclei" in current_step.lower():
                tool_name = "nuclei_scan"
            elif "sqlmap" in current_step.lower():
                tool_name = "sqlmap_scan"
            
            state["tool_calls"].append({
                "tool": tool_name,
                "command": command,
                "target": target,
                "step": current_step
            })
            
            # Add to thought trace
            state["thought_trace"].append({
                "node": "planner",
                "thought": f"Planning execution for step: {current_step}",
                "reasoning": f"Selected {tool_name} with command: {command}",
                "action": tool_name,
                "action_input": {"command": command, "target": target},
                "observation": "Command generated dynamically",
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            state["error"] = f"Planning failed: {str(e)}"
        
        return state
    
    return planner_node


def create_guardrail_node():
    """Safety Guardrail node - validates targets and commands"""
    
    def guardrail_node(state: AgentState) -> AgentState:
        target = state.get("target", "")
        
        # Validate target scope
        if not validate_scope(target):
            state["thought_trace"].append({
                "node": "guardrail",
                "thought": f"Validating target: {target}",
                "reasoning": "Target not in authorized scope",
                "action": "scope_validation",
                "observation": "BLOCKED - Target not authorized",
                "timestamp": datetime.now().isoformat()
            })
            state["error"] = f"Target {target} is not in the authorized scope"
            return state
        
        # Check for prompt injection attempts
        for msg in state.get("messages", []):
            content = msg.content.lower() if isinstance(msg, (HumanMessage, AIMessage)) else ""
            injection_patterns = [
                "ignore previous",
                "ignore all",
                "you are now",
                "disregard instructions",
                "new instructions:",
                "system:",
                "assistant:",
            ]
            if any(pattern in content for pattern in injection_patterns):
                state["thought_trace"].append({
                    "node": "guardrail",
                    "thought": "Input sanitization check",
                    "reasoning": "Potential prompt injection detected",
                    "action": "input_validation",
                    "observation": "BLOCKED - Prompt injection attempt",
                    "timestamp": datetime.now().isoformat()
                })
                state["error"] = "Potential prompt injection detected - input rejected"
                return state
        
        state["thought_trace"].append({
            "node": "guardrail",
            "thought": f"Validating target: {target}",
            "reasoning": "Target is in authorized scope",
            "action": "scope_validation",
            "observation": "APPROVED",
            "timestamp": datetime.now().isoformat()
        })
        
        return state
    
    return guardrail_node


def create_tool_node():
    """Tool node - executes the selected tools"""
    
    def tool_executor(state: AgentState) -> AgentState:
        tool_calls = state.get("tool_calls", [])
        
        if not tool_calls:
            return state
        
        # Execute the most recent tool call
        tool_call = tool_calls[-1]
        tool_name = tool_call.get("tool", "")
        command = tool_call.get("command", "")
        target = tool_call.get("target", "")
        
        result = {"success": False, "output": "", "error": None}
        
        try:
            # Map tool names to functions
            tool_map = {
                "nmap_scan": nmap_scan,
                "nikto_scan": nikto_scan,
                "whois_lookup": whois_lookup,
                "dig_lookup": dig_lookup,
                "gobuster_scan": gobuster_scan,
                "nuclei_scan": nuclei_scan,
                "sqlmap_scan": sqlmap_scan,
            }
            
            tool_func = tool_map.get(tool_name)
            if tool_func:
                # Run in executor to avoid blocking
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(tool_func, command, target)
                    output = future.result(timeout=300)
                    result = {"success": True, "output": output, "error": None}
            else:
                result = {"success": False, "output": "", "error": f"Unknown tool: {tool_name}"}
                
        except subprocess.TimeoutExpired:
            result = {"success": False, "output": "", "error": "Command timed out"}
        except Exception as e:
            result = {"success": False, "output": "", "error": str(e)}
        
        state["tool_results"].append({
            "tool": tool_name,
            "command": command,
            "result": result
        })
        
        # Add to thought trace
        state["thought_trace"].append({
            "node": "tool",
            "thought": f"Executing {tool_name}",
            "reasoning": f"Running command: {command}",
            "action": tool_name,
            "action_input": {"command": command},
            "observation": result.get("output", "")[:500] if result.get("success") else result.get("error", ""),
            "timestamp": datetime.now().isoformat()
        })
        
        return state
    
    return tool_executor


def create_reflection_node(llm):
    """Reflection node - analyzes results and decides next steps"""
    
    def reflection_node(state: AgentState) -> AgentState:
        target = state.get("target", "")
        tool_results = state.get("tool_results", [])
        plan = state.get("plan", [])
        iterations = state.get("iterations", 0)
        max_iterations = state.get("max_iterations", 20)
        
        if not tool_results:
            state["reflection_notes"] = "No results to analyze"
            return state
        
        last_result = tool_results[-1]
        output = last_result.get("result", {}).get("output", "")
        
        # Analyze the output using LLM
        messages = [
            SystemMessage(content=REFLECTION_PROMPT.format(
                output=output[:2000],
                target=target,
                current_step=state.get("current_step", "")
            ))
        ]
        
        try:
            response = llm.invoke(messages)
            analysis = response.content
            
            state["reflection_notes"] = analysis
            
            # Check if we should continue or stop
            done_indicators = [
                "completed", "finished", "no further", 
                "all findings", "full scan done"
            ]
            
            should_continue = not any(ind in analysis.lower() for ind in done_indicators)
            should_continue = should_continue and iterations < max_iterations
            
            # Determine next step
            if should_continue:
                current_idx = plan.index(state["current_step"]) if state["current_step"] in plan else -1
                if current_idx < len(plan) - 1:
                    state["current_step"] = plan[current_idx + 1]
                else:
                    # Generate next step dynamically
                    state["current_step"] = f"additional_enumeration_{iterations}"
            else:
                state["current_step"] = "COMPLETE"
            
            state["thought_trace"].append({
                "node": "reflection",
                "thought": "Analyzing tool output and planning next step",
                "reasoning": analysis[:200],
                "action": "reflection",
                "observation": f"Next step: {state['current_step']}",
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            state["reflection_notes"] = f"Reflection failed: {str(e)}"
            # Continue to next step on error
            iterations = state.get("iterations", 0) + 1
            if iterations < max_iterations:
                current_idx = plan.index(state["current_step"]) if state["current_step"] in plan else -1
                if current_idx < len(plan) - 1:
                    state["current_step"] = plan[current_idx + 1]
        
        state["iterations"] = iterations + 1
        return state
    
    return reflection_node


def create_router_node():
    """Router - decides which node to go to next"""
    
    def router(state: AgentState) -> str:
        # Check for errors
        if state.get("error"):
            return "end"
        
        # Check authorization
        if state.get("authorization_status") == "DENIED":
            return "end"
        
        # Check if complete
        if state.get("current_step") == "COMPLETE":
            return "end"
        
        # Check iterations
        if state.get("iterations", 0) >= state.get("max_iterations", 20):
            return "end"
        
        return "continue"
    
    return router


# ============================================================================
# Graph Compilation
# ============================================================================

def create_graph(llm):
    """Create the LangGraph state machine"""
    
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("supervisor", create_supervisor_node(llm))
    workflow.add_node("guardrail", create_guardrail_node())
    workflow.add_node("planner", create_planner_node(llm))
    workflow.add_node("tool", create_tool_node())
    workflow.add_node("reflection", create_reflection_node(llm))
    
    # Set entry point
    workflow.set_entry_point("supervisor")
    
    # Add edges
    workflow.add_edge("supervisor", "guardrail")
    workflow.add_edge("guardrail", "planner")
    workflow.add_edge("planner", "tool")
    workflow.add_edge("tool", "reflection")
    
    # Conditional routing from reflection
    workflow.add_conditional_edges(
        "reflection",
        create_router_node(),
        {
            "continue": "planner",
            "end": END
        }
    )
    
    return workflow.compile()


# ============================================================================
# Main Execution
# ============================================================================

async def run_pentest(target: str, task: str = "Perform comprehensive pentest", model: str = "llama3"):
    """Run the pentesting agent on a target"""
    
    llm = get_llm(model=model)
    graph = create_graph(llm)
    
    # Initialize state
    initial_state: AgentState = {
        "messages": [HumanMessage(content=task)],
        "target": target,
        "task": task,
        "plan": [],
        "current_step": "",
        "tool_calls": [],
        "tool_results": [],
        "thought_trace": [],
        "authorization_status": "PENDING",
        "reflection_notes": "",
        "iterations": 0,
        "max_iterations": 20,
        "error": None
    }
    
    # Run the graph
    result = await graph.ainvoke(initial_state)
    
    return result


if __name__ == "__main__":
    import asyncio
    
    async def main():
        result = await run_pentest("example.com", "Perform reconnaissance and vulnerability scan")
        print(json.dumps(result, indent=2, default=str))
    
    asyncio.run(main())
