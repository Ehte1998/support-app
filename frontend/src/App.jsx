import { useState, useEffect } from 'react'
import './index.css'

// Simple Admin Dashboard without calling
function AdminDashboard() {
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchMessages = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/messages')
      if (response.ok) {
        const data = await response.json()
        setMessages(data)
      }
    } catch (error) {
      console.error('Error:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchMessages()
  }, [])

  if (loading) {
    return (
      <div style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center' 
      }}>
        Loading admin dashboard...
      </div>
    )
  }

  return (
    <div style={{ padding: '2rem', minHeight: '100vh', background: '#f5f5f5' }}>
      <h1 style={{ marginBottom: '2rem' }}>Admin Dashboard</h1>
      <div style={{ background: 'white', padding: '2rem', borderRadius: '8px' }}>
        <h2>Messages ({messages.length})</h2>
        {messages.length === 0 ? (
          <p>No messages yet.</p>
        ) : (
          messages.map(msg => (
            <div key={msg._id} style={{ 
              border: '1px solid #ddd', 
              padding: '1rem', 
              margin: '1rem 0',
              borderRadius: '4px',
              background: '#fafafa'
            }}>
              <h3>{msg.name}</h3>
              <p>{msg.message}</p>
              <small>Status: {msg.status} | {new Date(msg.timestamp).toLocaleString()}</small>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// Simple User Interface
function UserInterface() {
  const [message, setMessage] = useState('')
  const [submitted, setSubmitted] = useState(false)

  const handleSubmit = async () => {
    if (!message.trim()) return

    try {
      const response = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: message.trim(),
          name: 'Anonymous',
          isAnonymous: true
        })
      })

      if (response.ok) {
        setSubmitted(true)
        setTimeout(() => {
          setSubmitted(false)
          setMessage('')
        }, 3000)
      }
    } catch (error) {
      alert('Error sending message')
    }
  }

  if (submitted) {
    return (
      <div style={{ 
        textAlign: 'center', 
        padding: '4rem 2rem',
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <div>
          <h2>Message sent successfully!</h2>
          <p>A counselor will reach out to you soon.</p>
        </div>
      </div>
    )
  }

  return (
    <div style={{ 
      maxWidth: '500px', 
      margin: '2rem auto', 
      padding: '2rem',
      background: 'white',
      borderRadius: '8px',
      minHeight: '60vh'
    }}>
      <h1>Share Your Feelings</h1>
      <p style={{ color: '#666', marginBottom: '2rem' }}>
        You're not alone. Share what's on your mind and get personalized support.
      </p>
      <textarea
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="What's on your mind?"
        style={{ 
          width: '100%', 
          height: '120px', 
          marginBottom: '1rem',
          padding: '1rem',
          border: '1px solid #ddd',
          borderRadius: '4px',
          resize: 'none'
        }}
      />
      <button 
        onClick={handleSubmit} 
        disabled={!message.trim()}
        style={{
          padding: '0.75rem 2rem',
          background: message.trim() ? '#3b82f6' : '#ccc',
          color: 'white',
          border: 'none',
          borderRadius: '4px',
          cursor: message.trim() ? 'pointer' : 'not-allowed'
        }}
      >
        Send Message
      </button>
    </div>
  )
}

function App() {
  const isAdmin = window.location.search.includes('admin=true')
  return isAdmin ? <AdminDashboard /> : <UserInterface />
}

export default App