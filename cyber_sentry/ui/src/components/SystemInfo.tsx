import { useState, useEffect } from 'react'
import { Tool, Shield, Activity, Lock, Zap } from 'lucide-react'

interface Tool {
  name: string
  description: string
  category: string
}

interface Guardrail {
  name: string
  description: string
}

interface SystemStatus {
  status: string
  active_sessions: number
  registered_agents: string[]
  available_tools: Tool[]
  guardrails: Guardrail[]
}

export function SystemInfo() {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null)

  useEffect(() => {
    fetch('/api/status')
      .then(res => res.json())
      .then(setSystemStatus)
      .catch(console.error)
  }, [])

  if (!systemStatus) {
    return (
      <div className="sidebar-section">
        <div className="loading">
          <div className="spinner" />
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="sidebar-section">
        <h3 className="sidebar-title">
          <Activity size={12} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
          System Status
        </h3>
        <div style={{ 
          display: 'flex', 
          flexDirection: 'column', 
          gap: '8px',
          padding: '12px',
          background: 'var(--bg-tertiary)',
          borderRadius: '6px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Status</span>
            <span style={{ color: 'var(--accent-success)' }}>{systemStatus.status}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Sessions</span>
            <span>{systemStatus.active_sessions}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Agents</span>
            <span>{systemStatus.registered_agents.length}</span>
          </div>
        </div>
      </div>

      <div className="sidebar-section">
        <h3 className="sidebar-title">
          <Tool size={12} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
          Available Tools
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {systemStatus.available_tools.slice(0, 5).map((tool) => (
            <div key={tool.name} className="tool-item">
              <Zap className="tool-icon" size={12} />
              <span style={{ color: 'var(--text-secondary)' }}>{tool.name}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="sidebar-section">
        <h3 className="sidebar-title">
          <Shield size={12} style={{ marginRight: '6px', verticalAlign: 'middle' }} />
          Security Guardrails
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {systemStatus.guardrails.map((guardrail) => (
            <div key={guardrail.name} className="guardrail-item">
              <span className="guardrail-status" />
              <span style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>
                {guardrail.name.replace(/_/g, ' ')}
              </span>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
