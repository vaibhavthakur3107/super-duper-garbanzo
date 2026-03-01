import { Search, Target, Zap, FileText } from 'lucide-react'
import type { Agent } from '../App'

interface AgentListProps {
  agents: Agent[]
  selectedAgent: string | null
  onSelectAgent: (name: string | null) => void
}

const agentIcons: Record<string, typeof Search> = {
  'Reconnaissance Agent': Search,
  'Vulnerability Agent': Target,
  'Exploitation Agent': Zap,
  'Reporting Agent': FileText,
}

export function AgentList({ agents, selectedAgent, onSelectAgent }: AgentListProps) {
  return (
    <div className="sidebar-section">
      <h3 className="sidebar-title">Red Team Agents</h3>
      <div className="agent-list">
        {agents.map((agent) => {
          const Icon = agentIcons[agent.name] || Search
          return (
            <div
              key={agent.name}
              className={`agent-item ${selectedAgent === agent.name ? 'active' : ''}`}
              onClick={() => onSelectAgent(selectedAgent === agent.name ? null : agent.name)}
            >
              <Icon className="agent-icon" size={18} />
              <span className="agent-name">{agent.name}</span>
              <span className={`agent-status ${agent.state}`} />
            </div>
          )
        })}
      </div>
    </div>
  )
}
