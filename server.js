const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? process.env.FRONTEND_URL 
      : "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const sendEmailNotification = async (userEmail, subject, message, callUrl) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: subject,
      html: `
        <h3>${subject}</h3>
        <p>${message}</p>
        <a href="${callUrl}" style="background: #10b981; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Join Session</a>
      `
    });
  } catch (error) {
    console.error('Email error:', error);
  }
};

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/support-app';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Message Schema with replies functionality
const messageSchema = new mongoose.Schema({
  message: {
    type: String,
    required: true
  },
  name: {
    type: String,
    default: 'Anonymous'
  },
  email: {
    type: String,
    required: false
  },
  phone: {
    type: String,
    required: false
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
  },
  paymentStatus: {
    type: String,
    enum: ['unpaid', 'paid'],
    default: 'unpaid'
  },
  paymentId: String,
  amountPaid: Number,
  paidAt: Date,
  replies: [{
    sender: {
      type: String,
      enum: ['user', 'admin'],
      required: true
    },
    message: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  lastReplyAt: {
    type: Date,
    default: Date.now
  }
});

const Message = mongoose.model('Message', messageSchema);

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running!' });
});

// Test Razorpay configuration
app.get('/api/test-razorpay', (req, res) => {
  try {
    res.json({
      keyId: process.env.RAZORPAY_KEY_ID || 'Missing',
      keySecret: process.env.RAZORPAY_KEY_SECRET ? 'Present' : 'Missing',
      razorpayInit: razorpay ? 'Initialized' : 'Failed'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all messages (for admin dashboard)
app.get('/api/messages', async (req, res) => {
  try {
    const messages = await Message.find().sort({ lastReplyAt: -1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Create new message
app.post('/api/messages', async (req, res) => {
  try {
    const { message, name, email, isAnonymous } = req.body;
    
    const newMessage = new Message({
      message,
      name: isAnonymous ? 'Anonymous' : (name || 'Anonymous'),
      email: email || '',
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

// Add reply to message
app.post('/api/messages/:id/reply', async (req, res) => {
  try {
    const { id } = req.params;
    const { message, sender } = req.body; // sender: 'user' or 'admin'
    
    const reply = {
      sender,
      message,
      timestamp: new Date()
    };
    
    const updatedMessage = await Message.findByIdAndUpdate(
      id,
      { 
        $push: { replies: reply },
        lastReplyAt: new Date()
      },
      { new: true }
    );
    
    if (!updatedMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Emit new reply to real-time listeners
    io.emit('newReply', { messageId: id, reply, sender });
    
    res.json({ success: true, reply });
  } catch (error) {
    console.error('Error adding reply:', error);
    res.status(500).json({ error: 'Failed to add reply' });
  }
});

// Payment Routes

// Create payment order
app.post('/api/create-payment-order', async (req, res) => {
  try {
    const { amount, messageId } = req.body; // amount in rupees
    
    const options = {
      amount: amount * 100, // Convert to paise
      currency: 'INR',
      receipt: `rcpt_${Date.now()}`, // Shortened receipt
      payment_capture: 1
    };

    const order = await razorpay.orders.create(options);
    
    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error('Error creating payment order:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create payment order' 
    });
  }
});

// Verify payment
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { 
      razorpay_order_id, 
      razorpay_payment_id, 
      razorpay_signature,
      messageId,
      amount 
    } = req.body;

    // Verify signature
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest('hex');

    if (expectedSignature === razorpay_signature) {
      // Payment successful - update message with payment info
      await Message.findByIdAndUpdate(messageId, {
        paymentStatus: 'paid',
        paymentId: razorpay_payment_id,
        amountPaid: amount / 100, // Convert back to rupees
        paidAt: new Date()
      });

      // Emit payment success to admin dashboard
      io.emit('paymentReceived', { messageId, amount: amount / 100 });

      res.json({
        success: true,
        message: 'Payment verified successfully'
      });
    } else {
      res.status(400).json({
        success: false,
        error: 'Invalid payment signature'
      });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({
      success: false,
      error: 'Payment verification failed'
    });
  }
});

// Get payment details
app.get('/api/payment/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const message = await Message.findById(messageId);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json({
      success: true,
      paymentStatus: message.paymentStatus || 'unpaid',
      amountPaid: message.amountPaid || 0,
      paidAt: message.paidAt
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get payment details' });
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

  // Call notification events
  socket.on('admin-start-call', async ({ messageId, callType }) => {
    console.log(`Admin starting ${callType} call for message:`, messageId);
    
    // Get message details for email
    try {
      const message = await Message.findById(messageId);
      if (message && message.email) {
        const callUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/chat/${messageId}`;
        await sendEmailNotification(
          message.email,
          'Incoming Call from Counselor',
          `Your counselor wants to start a ${callType} session with you.`,
          callUrl
        );
      }
    } catch (error) {
      console.error('Error sending email:', error);
    }
    
    // Notify user in message room about incoming call
    socket.to(`message-${messageId}`).emit('incoming-call', {
      messageId,
      callType, // 'webrtc', 'google-meet', 'zoom'
      timestamp: new Date()
    });
    
    // Update message status to in-call
    Message.findByIdAndUpdate(messageId, { status: 'in-call' })
      .then(() => {
        io.emit('messageStatusUpdate', { id: messageId, status: 'in-call' });
      })
      .catch(err => console.error('Error updating message status:', err));
  });

  // Handle user initiating calls
  socket.on('user-start-call', ({ messageId, callType }) => {
    console.log(`User starting ${callType} call for message:`, messageId);
    
    // Notify admin about user-initiated call
    socket.to('admin').emit('user-initiated-call', {
      messageId,
      callType,
      timestamp: new Date()
    });
    
    // Update message status to in-call
    Message.findByIdAndUpdate(messageId, { status: 'in-call' })
      .then(() => {
        io.emit('messageStatusUpdate', { id: messageId, status: 'in-call' });
      })
      .catch(err => console.error('Error updating message status:', err));
  });

  // Handle user accepting call
  socket.on('user-accept-call', ({ messageId }) => {
    console.log('User accepted call for message:', messageId);
    
    // Join both admin and user to the call room
    socket.join(`call-${messageId}`);
    
    // Notify admin that user accepted
    socket.to('admin').emit('call-accepted', { messageId });
  });

  // Handle call rejection
  socket.on('user-reject-call', ({ messageId }) => {
    console.log('User rejected call for message:', messageId);
    
    // Notify admin that user rejected
    socket.to('admin').emit('call-rejected', { messageId });
    
    // Reset message status back to pending
    Message.findByIdAndUpdate(messageId, { status: 'pending' })
      .then(() => {
        io.emit('messageStatusUpdate', { id: messageId, status: 'pending' });
      });
  });

  // WebRTC calling events
  socket.on('join-admin-call', (messageId) => {
    socket.join(`call-${messageId}`);
    console.log(`Admin joined call room: call-${messageId}`);
  });

  socket.on('join-user-call', (messageId) => {
    socket.join(`call-${messageId}`);
    console.log(`User joined call room: call-${messageId}`);
  });

  socket.on('start-call', (data) => {
    console.log('Call started for message:', data.messageId);
    socket.to(`call-${data.messageId}`).emit('incoming-call', {
      signal: data.signal,
      from: socket.id
    });
  });

  socket.on('accept-call', (data) => {
    console.log('Call accepted');
    io.to(data.to).emit('call-accepted', {
      signal: data.signal
    });
  });

  socket.on('reject-call', (data) => {
    console.log('Call rejected');
    io.to(data.to).emit('call-rejected');
  });

  socket.on('end-call', (data) => {
    console.log('Call ended for message:', data.messageId);
    socket.to(`call-${data.messageId}`).emit('call-ended');
    // Update message status to completed when call ends
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