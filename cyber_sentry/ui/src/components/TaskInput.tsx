import { useState, FormEvent } from 'react'
import { Play, Loader2 } from 'lucide-react'

interface TaskInputProps {
  onExecute: (task: string, target: string) => void
  isExecuting: boolean
}

export function TaskInput({ onExecute, isExecuting }: TaskInputProps) {
  const [task, setTask] = useState('')
  const [target, setTarget] = useState('')

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (task.trim() && !isExecuting) {
      onExecute(task, target)
    }
  }

  return (
    <div className="task-section">
      <form onSubmit={handleSubmit} className="task-input-wrapper">
        <input
          type="text"
          className="task-input"
          placeholder="Enter task description (e.g., 'Perform reconnaissance on target')"
          value={task}
          onChange={(e) => setTask(e.target.value)}
          disabled={isExecuting}
        />
        <input
          type="text"
          className="target-input"
          placeholder="Target (e.g., example.com)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={isExecuting}
        />
        <button 
          type="submit" 
          className="execute-btn"
          disabled={isExecuting || !task.trim()}
        >
          {isExecuting ? (
            <>
              <Loader2 className="spinner" style={{ animation: 'spin 1s linear infinite' }} />
              Executing
            </>
          ) : (
            <>
              <Play size={16} />
              Execute
            </>
          )}
        </button>
      </form>
    </div>
  )
}
