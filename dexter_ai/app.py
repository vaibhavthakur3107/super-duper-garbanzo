"""
Dexter AI Pentest - Streamlit Frontend
Thought Trace Visualizer for the Pentesting Agent
"""

import streamlit as st
import asyncio
import json
import uuid
import os
from datetime import datetime
from typing import Optional

# Configure page
st.set_page_config(
    page_title="Dexter AI Pentest",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add custom CSS
st.markdown("""
<style>
    /* Main theme */
    .stApp {
        background: #0a0e14;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #e6e6e6 !important;
    }
    
    /* Cards */
    .thought-card {
        background: #131820;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        border-left: 4px solid #58a6ff;
    }
    
    .thought-card.thinking {
        border-left-color: #d29922;
    }
    
    .thought-card.acting {
        border-left-color: #3fb950;
    }
    
    .thought-card.blocked {
        border-left-color: #f85149;
    }
    
    /* Status indicators */
    .status-badge {
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
    
    .status-authorized {
        background: #3fb950;
        color: #0a0e14;
    }
    
    .status-denied {
        background: #f85149;
        color: white;
    }
    
    .status-running {
        background: #d29922;
        color: #0a0e14;
    }
    
    /* Code blocks */
    code {
        background: #1a2029 !important;
        color: #e6e6e6 !important;
        padding: 2px 6px !important;
        border-radius: 4px;
    }
    
    /* Input fields */
    .stTextInput > div > div {
        background: #131820;
        border-color: #30363d;
    }
    
    /* Sidebar */
    .css-1d391kg {
        background: #131820;
    }
    
    /* Buttons */
    .stButton > button {
        background: #1f6feb;
        color: white;
        border: none;
    }
    
    .stButton > button:hover {
        background: #58a6ff;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        color: #58a6ff;
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background: #131820;
    }
</style>
""", unsafe_allow_html=True)

# Import the main module
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dexter_ai.main import run_pentest, get_llm
from dexter_ai.providers import PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER


# ============================================================================
# Session State Management
# ============================================================================

if 'current_session' not in st.session_state:
    st.session_state.current_session = None

if 'thought_trace' not in st.session_state:
    st.session_state.thought_trace = []

if 'is_running' not in st.session_state:
    st.session_state.is_running = False


# ============================================================================
# Helper Functions
# ============================================================================

def generate_session_id():
    return f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


async def run_agent_async(target: str, task: str, model: str, provider: str):
    """Run the agent asynchronously"""
    result = await run_pentest(target, task, model, provider)
    return result


def display_thought(thought: dict):
    """Display a single thought in the UI"""
    node = thought.get("node", "unknown")
    thought_text = thought.get("thought", "")
    reasoning = thought.get("reasoning", "")
    action = thought.get("action", "")
    observation = thought.get("observation", "")
    timestamp = thought.get("timestamp", "")
    
    # Determine card style based on node
    card_class = "thought-card"
    if node == "supervisor":
        card_class += " thinking"
    elif node == "tool":
        card_class += " acting"
    elif node == "guardrail" and "BLOCKED" in (observation or ""):
        card_class += " blocked"
    
    st.markdown(f'<div class="{card_class}">', unsafe_allow_html=True)
    
    # Header with node name and timestamp
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"**{node.upper()}**")
    with col2:
        st.caption(timestamp)
    
    # Thought
    if thought_text:
        st.markdown(f"**Thought:** {thought_text}")
    
    # Reasoning
    if reasoning:
        st.markdown(f"**Reasoning:** {reasoning}")
    
    # Action
    if action:
        st.markdown(f"**Action:** `{action}`")
    
    # Action Input
    action_input = thought.get("action_input", {})
    if action_input:
        with st.expander("Action Input"):
            st.json(action_input)
    
    # Observation
    if observation:
        with st.expander("Observation"):
            st.text(observation[:1000] + "..." if len(observation) > 1000 else observation)
    
    st.markdown('</div>', unsafe_allow_html=True)


def display_tool_result(result: dict):
    """Display tool execution result"""
    tool = result.get("tool", "unknown")
    command = result.get("command", "")
    result_data = result.get("result", {})
    
    success = result_data.get("success", False)
    output = result_data.get("output", "")
    error = result_data.get("error", "")
    
    with st.expander(f"Tool: {tool}", expanded=False):
        st.markdown(f"**Command:** `{command}`")
        
        if success:
            st.markdown("**Status:** ✅ Success")
            st.text_area("Output:", output, height=200)
        else:
            st.markdown("**Status:** ❌ Failed")
            if error:
                st.markdown(f"**Error:** {error}")


# ============================================================================
# Sidebar
# ============================================================================

def render_sidebar():
    """Render the sidebar with settings and info"""
    with st.sidebar:
        st.title("🛡️ Dexter AI Pentest")
        
        st.divider()
        
        # Provider selection
        st.subheader("LLM Provider")
        provider = st.selectbox(
            "Provider",
            [PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER],
            index=0,
            help="Select the LLM provider. Set the corresponding API key via environment variable."
        )

        # Model selection per provider
        st.subheader("Model Settings")
        if provider == PROVIDER_OLLAMA:
            model_options = ["llama3", "mistral", "codellama", "neural-chat"]
            default_idx = 0
        elif provider == PROVIDER_OPENAI:
            model_options = ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]
            default_idx = 0
        elif provider == PROVIDER_OPENROUTER:
            model_options = [
                "openai/gpt-4o-mini",
                "openai/gpt-4o",
                "anthropic/claude-3-haiku",
                "anthropic/claude-3.5-sonnet",
                "meta-llama/llama-3.1-8b-instruct:free",
                "mistralai/mistral-7b-instruct:free",
                "google/gemini-flash-1.5",
                "deepseek/deepseek-chat",
            ]
            default_idx = 0
        else:  # anthropic
            model_options = [
                "claude-3-haiku-20240307",
                "claude-3-5-sonnet-20241022",
                "claude-3-opus-20240229",
            ]
            default_idx = 0

        model = st.selectbox(
            "Model",
            model_options,
            index=default_idx,
            help="Select the model to use for the chosen provider"
        )
        
        st.divider()
        
        # Authorized scopes
        st.subheader("Authorized Scopes")
        scopes = st.text_area(
            "Allowed Targets",
            value="example.com, test.local, 127.0.0.1, localhost",
            height=80,
            help="Comma-separated list of authorized targets"
        )
        
        st.divider()
        
        # Session info
        st.subheader("Session Info")
        if st.session_state.current_session:
            st.metric("Session", st.session_state.current_session[:20] + "...")
            st.metric("Thoughts", len(st.session_state.thought_trace))
        
        st.divider()
        
        # About
        st.caption("""
        **Dexter AI Pentest** v1.0.0
        
        Red Team Pentesting Agent
        Built with LangGraph + Ollama/OpenAI/Anthropic/OpenRouter
        """)
        
        return model, provider, scopes


# ============================================================================
# Main Content
# ============================================================================

def main():
    """Main application"""
    
    model, provider, scopes = render_sidebar()
    
    # Main content area
    st.title("🛡️ Dexter AI Pentest")
    st.markdown("### Red Team Pentesting Agent")
    
    # Task input section
    with st.container():
        col1, col2 = st.columns([3, 1])
        
        with col1:
            target = st.text_input(
                "Target",
                placeholder="example.com",
                help="Enter the target domain or IP address"
            )
        
        with col2:
            task_type = st.selectbox(
                "Task Type",
                [
                    "Full Pentest",
                    "Reconnaissance Only",
                    "Vulnerability Scan",
                    "Web Enumeration",
                    "Port Scan"
                ]
            )
    
    # Task description
    task_descriptions = {
        "Full Pentest": "Perform comprehensive penetration testing",
        "Reconnaissance Only": "Gather information about the target",
        "Vulnerability Scan": "Scan for known vulnerabilities",
        "Web Enumeration": "Enumerate web directories and files",
        "Port Scan": "Scan for open ports and services"
    }
    task = task_descriptions.get(task_type, "Perform penetration testing")
    
    # Execute button
    if st.button("🚀 Execute Assessment", type="primary", disabled=st.session_state.is_running):
        if not target:
            st.error("Please enter a target")
        else:
            # Check scope
            from dexter_ai.guardrails.scope_validator import validate_scope
            if not validate_scope(target):
                st.error(f"Target '{target}' is not in the authorized scope!")
                st.info("Add the target to the Authorized Scopes in the sidebar")
            else:
                # Start execution
                st.session_state.is_running = True
                st.session_state.current_session = generate_session_id()
                st.session_state.thought_trace = []
                
                # Run agent
                try:
                    result = asyncio.run(run_agent_async(target, task, model, provider))
                    
                    # Update thought trace
                    st.session_state.thought_trace = result.get("thought_trace", [])
                    st.session_state.is_running = False
                    
                    # Show results
                    st.success("Assessment complete!")
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                    st.session_state.is_running = False
    
    # Running indicator
    if st.session_state.is_running:
        st.warning("🔄 Assessment in progress... Watch the thought trace below.")
        
        # Auto-refresh placeholder
        placeholder = st.empty()
        with placeholder:
            st.markdown("""
            <div style="text-align: center; padding: 40px;">
                <div class="spinner">◌</div>
                <p>Agent is reasoning...</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Thought Trace Display
    st.divider()
    st.subheader("🧠 Thought Trace")
    
    if st.session_state.thought_trace:
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Thoughts", len(st.session_state.thought_trace))
        
        # Count nodes by type
        node_counts = {}
        for thought in st.session_state.thought_trace:
            node = thought.get("node", "unknown")
            node_counts[node] = node_counts.get(node, 0) + 1
        
        with col2:
            st.metric("Supervisor", node_counts.get("supervisor", 0))
        
        with col3:
            st.metric("Tools Executed", node_counts.get("tool", 0))
        
        with col4:
            st.metric("Reflections", node_counts.get("reflection", 0))
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            filter_node = st.selectbox(
                "Filter by Node",
                ["All"] + list(set(t.get("node", "") for t in st.session_state.thought_trace))
            )
        
        with col2:
            show_only_latest = st.checkbox("Show only latest", False)
        
        # Filter thoughts
        filtered_thoughts = st.session_state.thought_trace
        if filter_node != "All":
            filtered_thoughts = [t for t in filtered_thoughts if t.get("node") == filter_node]
        
        if show_only_latest:
            filtered_thoughts = filtered_thoughts[-5:]
        
        # Display thoughts
        for thought in filtered_thoughts:
            display_thought(thought)
    
    else:
        st.info("👈 Enter a target and click 'Execute Assessment' to start the pentest.")
        
        # Show example thought trace
        st.markdown("### Example Thought Trace")
        
        example_thoughts = [
            {
                "node": "supervisor",
                "thought": "Analyzing target and creating attack plan",
                "reasoning": "Target is example.com - creating phased approach",
                "action": "plan_generation",
                "observation": "Plan: reconnaissance, port_scan, web_enumeration, vulnerability_scan",
                "timestamp": datetime.now().isoformat()
            },
            {
                "node": "guardrail",
                "thought": "Validating target scope",
                "reasoning": "Target is in authorized scope",
                "action": "scope_validation",
                "observation": "APPROVED",
                "timestamp": datetime.now().isoformat()
            },
            {
                "node": "planner",
                "thought": "Planning reconnaissance phase",
                "reasoning": "Will use nmap for initial port scan",
                "action": "nmap_scan",
                "action_input": {"command": "nmap -sV -sC -T4 example.com"},
                "observation": "Command generated: nmap -sV -sC -T4 example.com",
                "timestamp": datetime.now().isoformat()
            }
        ]
        
        for thought in example_thoughts:
            display_thought(thought)
    
    # Tool Results Section
    if st.session_state.thought_trace:
        tool_results = [t for t in st.session_state.thought_trace if t.get("node") == "tool"]
        
        if tool_results:
            st.divider()
            st.subheader("🔧 Tool Results")
            
            for thought in tool_results:
                # Check if there's a result
                tool_name = thought.get("action", "")
                if tool_name:
                    st.markdown(f"**{tool_name}**")
                    observation = thought.get("observation", "")
                    if observation:
                        st.text(observation[:500] + "..." if len(observation) > 500 else observation)
        
        # ── Report Export ──────────────────────────────────────────────────────
        st.divider()
        st.subheader("📄 Export Report")
        
        if st.button("📥 Generate Markdown Report"):
            report_lines = [
                "# Dexter AI Pentest – Penetration Test Report",
                "",
                f"**Session:** {st.session_state.current_session or 'N/A'}",
                f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "---",
                "",
                "## Thought Trace",
                "",
            ]
            for t in st.session_state.thought_trace:
                report_lines.append(f"### [{t.get('node', '').upper()}] {t.get('action', '')}")
                if t.get("thought"):
                    report_lines.append(f"**Thought:** {t['thought']}")
                if t.get("reasoning"):
                    report_lines.append(f"**Reasoning:** {t['reasoning']}")
                if t.get("observation"):
                    report_lines.append(f"**Observation:**\n```\n{t['observation']}\n```")
                report_lines.append("")
            
            report_md = "\n".join(report_lines)
            st.download_button(
                label="⬇️ Download report.md",
                data=report_md,
                file_name="dexter_ai_report.md",
                mime="text/markdown",
            )
            with st.expander("Preview Report"):
                st.markdown(report_md)


if __name__ == "__main__":
    main()
