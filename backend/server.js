const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const http = require('http');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173", // Frontend URL
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection (we'll use a simple local setup for now)
// For production, you'd use MongoDB Atlas
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/support-app';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Message Schema
const messageSchema = new mongoose.Schema({
  message: {
    type: String,
    required: true
  },
  name: {
    type: String,
    default: 'Anonymous'
  },
  isAnonymous: {
    type: Boolean,
    default: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['pending', 'in-call', 'completed'],
    default: 'pending'
  }
});

const Message = mongoose.model('Message', messageSchema);

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running!' });
});

// Get all messages (for your admin dashboard)
app.get('/api/messages', async (req, res) => {
  try {
    const messages = await Message.find().sort({ timestamp: -1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Create new message
app.post('/api/messages', async (req, res) => {
  try {
    const { message, name, isAnonymous } = req.body;
    
    const newMessage = new Message({
      message,
      name: isAnonymous ? 'Anonymous' : (name || 'Anonymous'),
      isAnonymous
    });

    await newMessage.save();
    
    // Emit to admin dashboard in real-time
    io.emit('newMessage', newMessage);
    
    res.status(201).json({ 
      success: true, 
      message: 'Message received successfully',
      id: newMessage._id
    });
  } catch (error) {
    console.error('Error saving message:', error);
    res.status(500).json({ error: 'Failed to save message' });
  }
});

// Update message status
app.patch('/api/messages/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const message = await Message.findByIdAndUpdate(
      id, 
      { status }, 
      { new: true }
    );
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Emit status update to admin dashboard
    io.emit('messageStatusUpdate', { id, status });
    
    res.json(message);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update message status' });
  }
});

// Initiate call using Exotel
app.post('/api/call/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const { userPhoneNumber, counselorPhoneNumber } = req.body;
    
    // Find the message
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Make call using Exotel
    const callData = {
      From: userPhoneNumber,
      To: counselorPhoneNumber,
      CallerId: EXOTEL_CONFIG.exoPhone,
      CallType: 'trans',
      TimeLimit: 3600, // 1 hour limit
      TimeOut: 30, // 30 seconds timeout
      StatusCallback: `http://localhost:${process.env.PORT}/api/call-status/${messageId}`
    };

    const response = await axios.post(
      `${EXOTEL_CONFIG.baseUrl}/Calls/connect.json`,
      new URLSearchParams(callData),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    // Update message status to in-call
    await Message.findByIdAndUpdate(messageId, { status: 'in-call' });
    
    // Emit status update
    io.emit('messageStatusUpdate', { id: messageId, status: 'in-call' });

    res.json({
      success: true,
      callSid: response.data.Call.Sid,
      status: response.data.Call.Status,
      message: 'Call initiated successfully'
    });

  } catch (error) {
    console.error('Error initiating Exotel call:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to initiate call',
      details: error.response?.data || error.message
    });
  }
});

// Handle call status updates from Exotel
app.post('/api/call-status/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const { CallStatus, CallSid } = req.body;

    console.log('Call status update:', { messageId, CallStatus, CallSid });

    // Update message status based on call status
    let newStatus = 'pending';
    switch (CallStatus) {
      case 'in-progress':
        newStatus = 'in-call';
        break;
      case 'completed':
      case 'failed':
      case 'busy':
      case 'no-answer':
        newStatus = 'completed';
        break;
    }

    await Message.findByIdAndUpdate(messageId, { status: newStatus });
    
    // Emit status update
    io.emit('messageStatusUpdate', { id: messageId, status: newStatus });

    res.json({ success: true });
  } catch (error) {
    console.error('Error handling call status:', error);
    res.status(500).json({ error: 'Failed to update call status' });
  }
});

// Get call details
app.get('/api/call-details/:callSid', async (req, res) => {
  try {
    const { callSid } = req.params;
    
    const response = await axios.get(
      `${EXOTEL_CONFIG.baseUrl}/Calls/${callSid}.json`
    );

    res.json({
      success: true,
      call: response.data.Call
    });
  } catch (error) {
    console.error('Error fetching call details:', error);
    res.status(500).json({ error: 'Failed to fetch call details' });
  }
});

// Socket.io for real-time updates and WebRTC signaling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // Admin joins admin room
  socket.on('join-admin', () => {
    socket.join('admin');
    console.log('Admin joined:', socket.id);
    socket.emit('admin-connected');
  });

  // User joins message-specific room
  socket.on('join-message-room', (messageId) => {
    socket.join(`message-${messageId}`);
    console.log(`User joined message room: ${messageId}`);
    socket.emit('room-joined', messageId);
  });

  // WebRTC signaling for calls
  socket.on('initiate-call', (data) => {
    console.log('Call initiated for message:', data.messageId);
    socket.to(`message-${data.messageId}`).emit('incoming-call', {
      signal: data.signal,
      from: socket.id,
      messageId: data.messageId,
      callerType: data.callerType
    });
  });

  socket.on('accept-call', (data) => {
    console.log('Call accepted');
    io.to(data.to).emit('call-accepted', {
      signal: data.signal,
      messageId: data.messageId
    });
  });

  socket.on('reject-call', (data) => {
    io.to(data.to).emit('call-rejected', { messageId: data.messageId });
  });

  socket.on('end-call', (data) => {
    socket.to(`message-${data.messageId}`).emit('call-ended', { messageId: data.messageId });
    // Update message status to completed
    Message.findByIdAndUpdate(data.messageId, { status: 'completed' })
      .then(() => {
        io.emit('messageStatusUpdate', { id: data.messageId, status: 'completed' });
      });
  });

  // Regular message updates
  socket.on('adminStatusUpdate', (status) => {
    console.log('Admin status updated to:', status);
    socket.broadcast.emit('adminStatusChanged', status);
  });
  
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Frontend should connect to: http://localhost:${PORT}`);
});