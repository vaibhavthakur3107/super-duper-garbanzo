import { 
  Brain, 
  ChevronRight, 
  Lightbulb, 
  Footprints, 
  Eye, 
  CheckCircle,
  AlertCircle,
  Clock
} from 'lucide-react'
import type { Thought } from '../App'

interface ThoughtTraceProps {
  thoughts: Thought[]
  selectedAgent: string | null
}

function getStateIcon(state: string) {
  switch (state) {
    case 'thinking':
      return <Brain size={14} />
    case 'acting':
      return <Footprints size={14} />
    case 'observing':
      return <Eye size={14} />
    case 'completed':
      return <CheckCircle size={14} />
    case 'blocked':
      return <AlertCircle size={14} />
    default:
      return <Clock size={14} />
  }
}

function formatTimestamp(timestamp: string) {
  try {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    })
  } catch {
    return timestamp
  }
}

export function ThoughtTrace({ thoughts, selectedAgent }: ThoughtTraceProps) {
  const filteredThoughts = selectedAgent 
    ? thoughts.filter(t => t.agent === selectedAgent)
    : thoughts

  if (filteredThoughts.length === 0) {
    return (
      <div className="thought-trace">
        <div className="thoughts-panel">
          <div className="panel-header">
            <span className="panel-title">
              <Brain size={16} />
              Thought Trace
            </span>
          </div>
          <div className="empty-state">
            <Lightbulb className="empty-icon" />
            <p className="empty-text">No thoughts yet. Execute a task to see the reasoning trace.</p>
          </div>
        </div>
        <div className="details-panel">
          <div className="detail-card">
            <div className="detail-header">Agent Reasoning Flow</div>
            <div className="detail-content">
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                The Thought Trace visualizes the ReAct (Reasoning + Acting) reasoning chain 
                of each agent. Watch as agents:
              </p>
              <ul style={{ marginTop: '12px', paddingLeft: '16px', color: 'var(--text-secondary)', fontSize: '13px' }}>
                <li style={{ marginBottom: '8px' }}><strong>Think</strong> - Analyze the task and context</li>
                <li style={{ marginBottom: '8px' }}><strong>Act</strong> - Execute tool actions</li>
                <li style={{ marginBottom: '8px' }}><strong>Observe</strong> - Process results and iterate</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="thought-trace">
      <div className="thoughts-panel">
        <div className="panel-header">
          <span className="panel-title">
            <Brain size={16} />
            Thought Trace
          </span>
          <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
            {filteredThoughts.length} step{filteredThoughts.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="thought-list">
          {filteredThoughts.map((thought, index) => (
            <div 
              key={thought.id} 
              className={`thought-item ${thought.state}`}
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="thought-header">
                <span className="thought-agent">
                  {getStateIcon(thought.state)}
                  <span style={{ marginLeft: '6px' }}>{thought.agent}</span>
                </span>
                <span className="thought-timestamp">
                  {formatTimestamp(thought.timestamp)}
                </span>
              </div>
              
              <div className="thought-content">
                <div className="thought-label">Reasoning</div>
                <p className="thought-reasoning">{thought.reasoning || thought.thought}</p>
              </div>

              {thought.action && (
                <div className="thought-action">
                  <div className="thought-label">Action</div>
                  <div>
                    <span className="thought-action-type">{thought.action}</span>
                    {thought.action_input && Object.keys(thought.action_input).length > 0 && (
                      <div className="thought-action-input">
                        {JSON.stringify(thought.action_input, null, 2)}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {thought.observation && (
                <div className="thought-observation">
                  <div className="thought-label">Observation</div>
                  <p className="thought-observation-text">
                    {thought.observation.length > 200 
                      ? thought.observation.slice(0, 200) + '...'
                      : thought.observation}
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="details-panel">
        <div className="detail-card">
          <div className="detail-header">ReAct Reasoning Flow</div>
          <div className="detail-content">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Brain size={16} style={{ color: 'var(--accent-warning)' }} />
              <span style={{ fontSize: '13px' }}>Think →</span>
              <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontSize: '13px' }}>Act →</span>
              <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
              <span style={{ fontSize: '13px' }}>Observe</span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '12px', lineHeight: '1.6' }}>
              Each agent follows the ReAct paradigm: analyzing the situation, selecting an action,
              executing it, observing results, and iterating until the task is complete.
            </p>
          </div>
        </div>

        <div className="detail-card">
          <div className="detail-header">Session Info</div>
          <div className="detail-content">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Status</span>
                <span style={{ color: 'var(--accent-success)' }}>Completed</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Agents Active</span>
                <span>{filteredThoughts.length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
