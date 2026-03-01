import { useState, useEffect, useCallback } from 'react'
import { 
  Shield, 
  Brain, 
  Target, 
  AlertTriangle, 
  FileText, 
  Search, 
  Zap, 
  Play,
  Activity,
  Terminal,
  Lock,
  ChevronRight
} from 'lucide-react'
import { ThoughtTrace } from './components/ThoughtTrace'
import { TaskInput } from './components/TaskInput'
import { AgentList } from './components/AgentList'
import { SystemInfo } from './components/SystemInfo'

export interface Thought {
  id: string
  timestamp: string
  agent: string
  thought: string
  action: string | null
  action_input: Record<string, unknown>
  observation: string | null
  reasoning: string
  confidence: number
  state: string
}

export interface Agent {
  name: string
  state: string
  last_thought?: Thought
}

export interface Task {
  session_id: string
  status: string
  task: string
  start_time: string
  results: Thought[]
}

function App() {
  const [agents, setAgents] = useState<Agent[]>([
    { name: 'Reconnaissance Agent', state: 'idle' },
    { name: 'Vulnerability Agent', state: 'idle' },
    { name: 'Exploitation Agent', state: 'idle' },
    { name: 'Reporting Agent', state: 'idle' },
  ])
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null)
  const [thoughts, setThoughts] = useState<Thought[]>([])
  const [currentTask, setCurrentTask] = useState<Task | null>(null)
  const [isExecuting, setIsExecuting] = useState(false)
  const [status, setStatus] = useState<'idle' | 'operational'>('operational')

  const executeTask = useCallback(async (task: string, target: string) => {
    setIsExecuting(true)
    
    // Update agent states
    setAgents(prev => prev.map(a => ({ ...a, state: 'thinking' })))
    
    try {
      const response = await fetch('/api/tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task, target }),
      })
      
      if (!response.ok) throw new Error('Task execution failed')
      
      const result = await response.json()
      setCurrentTask(result)
      
      // Extract thoughts from results
      const allThoughts: Thought[] = []
      result.results?.forEach((r: { to_dict?: () => Thought }) => {
        if (r.to_dict) {
          allThoughts.push(r.to_dict())
        }
      })
      setThoughts(allThoughts)
      
      // Update agent states based on results
      setAgents(prev => prev.map(a => ({ ...a, state: 'idle' })))
    } catch (error) {
      console.error('Task execution error:', error)
      setAgents(prev => prev.map(a => ({ ...a, state: 'error' })))
    } finally {
      setIsExecuting(false)
    }
  }, [])

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <Shield className="logo-icon" />
          <span className="logo-text">Cyber-Sentry AI</span>
        </div>
        <div className="header-status">
          <span className="status-dot" />
          <span>System {status}</span>
        </div>
      </header>

      <aside className="sidebar">
        <AgentList 
          agents={agents} 
          selectedAgent={selectedAgent}
          onSelectAgent={setSelectedAgent}
        />
        
        <SystemInfo />
      </aside>

      <main className="main-content">
        <TaskInput 
          onExecute={executeTask}
          isExecuting={isExecuting}
        />
        
        <ThoughtTrace 
          thoughts={thoughts}
          selectedAgent={selectedAgent}
        />
      </main>
    </div>
  )
}

export default App
