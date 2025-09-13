import { useState, useEffect, useRef } from 'react'
import io from 'socket.io-client'
import Peer from 'simple-peer'

function AdminDashboard() {
  const [messages, setMessages] = useState([])
  const [status, setStatus] = useState('offline')
  const [loading, setLoading] = useState(true)
  const [socket, setSocket] = useState(null)
  const [notification, setNotification] = useState(null)
  
  // Call state
  const [activeCall, setActiveCall] = useState(null)
  const [stream, setStream] = useState(null)
  const [callAccepted, setCallAccepted] = useState(false)
  const [mediaReady, setMediaReady] = useState(false)

  const myVideo = useRef()
  const userVideo = useRef()
  const connectionRef = useRef()

  // Initialize Socket.io connection and media
  useEffect(() => {
    const newSocket = io('http://localhost:5000')
    setSocket(newSocket)

    // Join admin room
    newSocket.emit('join-admin')

    // Set up media when starting a call
    const setupMedia = async () => {
      try {
        const currentStream = await navigator.mediaDevices.getUserMedia({ 
          video: true, 
          audio: true 
        })
        setStream(currentStream)
        setMediaReady(true)
        if (myVideo.current && activeCall) {
          myVideo.current.srcObject = currentStream
        }
      } catch (error) {
        // Fallback to audio only
        try {
          const audioStream = await navigator.mediaDevices.getUserMedia({ 
            video: false, 
            audio: true 
          })
          setStream(audioStream)
          setMediaReady(true)
        } catch (audioError) {
          console.error('Media access denied:', audioError)
        }
      }
    }

    if (activeCall && !stream) {
      setupMedia()
    }

    // Listen for new messages
    newSocket.on('newMessage', (newMessage) => {
      setMessages(prev => [newMessage, ...prev])
      setNotification({
        type: 'new_message',
        message: `New message from ${newMessage.name}`,
        timestamp: Date.now()
      })
    })

    // Listen for call acceptance
    newSocket.on('call-accepted', (data) => {
      setCallAccepted(true)
      connectionRef.current.signal(data.signal)
    })

    // Listen for call rejection/end
    newSocket.on('call-rejected', () => {
      endCall()
      alert('Call was rejected')
    })

    newSocket.on('call-ended', () => {
      endCall()
    })

    return () => {
      if (stream) {
        stream.getTracks().forEach(track => track.stop())
      }
      newSocket.close()
    }
  }, [activeCall])

  // Fetch messages
  const fetchMessages = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/messages')
      if (response.ok) {
        const data = await response.json()
        setMessages(data)
      }
    } catch (error) {
      console.error('Error fetching messages:', error)
    } finally {
      setLoading(false)
    }
  }

  // Update message status
  const updateMessageStatus = async (messageId, newStatus) => {
    try {
      const response = await fetch(`http://localhost:5000/api/messages/${messageId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      })

      if (response.ok) {
        setMessages(messages.map(msg => 
          msg._id === messageId ? { ...msg, status: newStatus } : msg
        ))
      }
    } catch (error) {
      console.error('Error updating message status:', error)
    }
  }

  // Start WebRTC call
  const startCall = async (messageId) => {
    if (!stream || !mediaReady) {
      alert('Please wait for media to initialize')
      return
    }

    setActiveCall(messageId)
    
    const peer = new Peer({ initiator: true, trickle: false, stream: stream })

    peer.on('signal', (data) => {
      socket.emit('initiate-call', {
        signal: data,
        messageId: messageId,
        callerType: 'admin'
      })
    })

    peer.on('stream', (currentStream) => {
      if (userVideo.current) {
        userVideo.current.srcObject = currentStream
      }
    })

    connectionRef.current = peer
    
    // Update message status
    updateMessageStatus(messageId, 'in-call')
  }

  // End call
  const endCall = () => {
    if (activeCall) {
      socket.emit('end-call', { messageId: activeCall })
      updateMessageStatus(activeCall, 'completed')
    }

    setActiveCall(null)
    setCallAccepted(false)
    
    if (connectionRef.current) {
      connectionRef.current.destroy()
    }

    if (stream) {
      stream.getTracks().forEach(track => track.stop())
      setStream(null)
      setMediaReady(false)
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
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      }}>
        <div style={{ color: 'white', fontSize: '1.2rem' }}>Loading dashboard...</div>
      </div>
    )
  }

  const pendingCount = messages.filter(msg => msg.status === 'pending').length
  const inCallCount = messages.filter(msg => msg.status === 'in-call').length
  const completedCount = messages.filter(msg => msg.status === 'completed').length

  return (
    <div style={{ 
      minHeight: '100vh', 
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      padding: '2rem'
    }}>
      {/* Active Call Overlay */}
      {activeCall && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100vw',
          height: '100vh',
          background: 'rgba(0, 0, 0, 0.95)',
          zIndex: 1000,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'white'
        }}>
          <h2 style={{ marginBottom: '2rem' }}>Support Call in Progress</h2>
          
          <div style={{ display: 'flex', gap: '2rem', marginBottom: '2rem' }}>
            <div style={{ textAlign: 'center' }}>
              <h3>You (Counselor)</h3>
              <video
                ref={myVideo}
                muted
                autoPlay
                style={{
                  width: '300px',
                  height: '200px',
                  border: '2px solid white',
                  borderRadius: '8px',
                  backgroundColor: '#374151'
                }}
              />
            </div>
            
            {callAccepted && (
              <div style={{ textAlign: 'center' }}>
                <h3>User</h3>
                <video
                  ref={userVideo}
                  autoPlay
                  style={{
                    width: '300px',
                    height: '200px',
                    border: '2px solid white',
                    borderRadius: '8px',
                    backgroundColor: '#374151'
                  }}
                />
              </div>
            )}
          </div>

          <div style={{ marginBottom: '2rem' }}>
            {!callAccepted ? (
              <p style={{ color: '#fbbf24' }}>Calling user... Waiting for them to accept</p>
            ) : (
              <p style={{ color: '#10b981' }}>Call connected successfully</p>
            )}
          </div>

          <button
            onClick={endCall}
            style={{
              padding: '1rem 2rem',
              background: '#ef4444',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            End Call
          </button>
        </div>
      )}

      {/* Notifications */}
      {notification && (
        <div style={{
          position: 'fixed',
          top: '1rem',
          right: '1rem',
          background: '#10b981',
          color: 'white',
          padding: '1rem 1.5rem',
          borderRadius: '0.5rem',
          zIndex: 999
        }}>
          <span>🔔 {notification.message}</span>
          <button
            onClick={() => setNotification(null)}
            style={{
              background: 'none',
              border: 'none',
              color: 'white',
              cursor: 'pointer',
              marginLeft: '0.5rem'
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Header */}
      <div style={{ 
        background: 'white', 
        borderRadius: '1rem', 
        padding: '2rem', 
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: 'bold', margin: 0 }}>
            Support Dashboard
          </h1>
          <button
            onClick={() => setStatus(status === 'online' ? 'offline' : 'online')}
            style={{
              padding: '0.75rem 1.5rem',
              borderRadius: '0.5rem',
              border: 'none',
              fontWeight: '600',
              cursor: 'pointer',
              backgroundColor: status === 'online' ? '#10b981' : '#6b7280',
              color: 'white'
            }}
          >
            {status === 'online' ? '🟢 Online' : '🔴 Offline'}
          </button>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
          <div style={{ background: '#fef3c7', padding: '1.5rem', borderRadius: '0.5rem', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#d97706' }}>{pendingCount}</div>
            <div style={{ color: '#92400e', fontSize: '0.875rem' }}>Pending</div>
          </div>
          <div style={{ background: '#dbeafe', padding: '1.5rem', borderRadius: '0.5rem', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#2563eb' }}>{inCallCount}</div>
            <div style={{ color: '#1e40af', fontSize: '0.875rem' }}>In Call</div>
          </div>
          <div style={{ background: '#dcfce7', padding: '1.5rem', borderRadius: '0.5rem', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#16a34a' }}>{completedCount}</div>
            <div style={{ color: '#15803d', fontSize: '0.875rem' }}>Completed</div>
          </div>
        </div>
      </div>

      {/* Messages */}
      <div style={{ 
        background: 'white', 
        borderRadius: '1rem', 
        padding: '2rem'
      }}>
        <h2 style={{ marginBottom: '1.5rem' }}>Messages ({messages.length})</h2>
        
        {messages.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
            No messages yet.
          </div>
        ) : (
          messages.map((message) => (
            <div
              key={message._id}
              style={{
                border: '1px solid #ddd',
                borderRadius: '0.5rem',
                padding: '1.5rem',
                marginBottom: '1rem',
                background: message.status === 'pending' ? '#fffbeb' : 'white'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <div>
                  <div style={{ fontWeight: 'bold' }}>{message.name}</div>
                  <div style={{ fontSize: '0.875rem', color: '#666' }}>
                    {new Date(message.timestamp).toLocaleString()}
                  </div>
                </div>
                <span style={{
                  padding: '0.25rem 0.75rem',
                  borderRadius: '9999px',
                  fontSize: '0.75rem',
                  background: message.status === 'pending' ? '#fef3c7' : 
                             message.status === 'in-call' ? '#dbeafe' : '#dcfce7',
                  color: message.status === 'pending' ? '#92400e' : 
                         message.status === 'in-call' ? '#1e40af' : '#15803d'
                }}>
                  {message.status.toUpperCase()}
                </span>
              </div>

              <div style={{ 
                marginBottom: '1rem',
                padding: '1rem',
                background: '#f9fafb',
                borderRadius: '0.375rem',
                borderLeft: '4px solid #3b82f6'
              }}>
                {message.message}
              </div>

              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {message.status === 'pending' && (
                  <button
                    onClick={() => startCall(message._id)}
                    disabled={activeCall !== null}
                    style={{
                      padding: '0.5rem 1rem',
                      background: activeCall ? '#9ca3af' : '#10b981',
                      color: 'white',
                      border: 'none',
                      borderRadius: '0.375rem',
                      cursor: activeCall ? 'not-allowed' : 'pointer'
                    }}
                  >
                    📞 Start Video Call
                  </button>
                )}
                
                {message.status === 'in-call' && message._id === activeCall && (
                  <button
                    onClick={endCall}
                    style={{
                      padding: '0.5rem 1rem',
                      background: '#ef4444',
                      color: 'white',
                      border: 'none',
                      borderRadius: '0.375rem',
                      cursor: 'pointer'
                    }}
                  >
                    📴 End Call
                  </button>
                )}

                {message.status === 'in-call' && message._id !== activeCall && (
                  <button
                    onClick={() => updateMessageStatus(message._id, 'completed')}
                    style={{
                      padding: '0.5rem 1rem',
                      background: '#10b981',
                      color: 'white',
                      border: 'none',
                      borderRadius: '0.375rem',
                      cursor: 'pointer'
                    }}
                  >
                    ✅ Mark Complete
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default AdminDashboard