const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
const Razorpay = require('razorpay');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      
      const allowedOrigins = process.env.NODE_ENV === 'production' 
        ? [
            "https://support-app-2.vercel.app",
            process.env.FRONTEND_URL,
            "https://support-app-1-m6kf.onrender.com"
          ]
        : ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"];
      
      if (allowedOrigins.includes(origin) || origin.endsWith('.vercel.app')) {
        return callback(null, true);
      }
      
      callback(new Error('Not allowed by CORS'));
    },
    credentials: true
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-jwt-secret-change-in-production';

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, etc)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.NODE_ENV === 'production' 
      ? [
          "https://support-app-2.vercel.app",
          process.env.FRONTEND_URL
        ]
      : ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"];
    
    // Allow any Vercel deployment URL or specific allowed origins
    if (allowedOrigins.includes(origin) || 
        origin.endsWith('.vercel.app') || 
        origin === "https://support-app-1-m6kf.onrender.com") {
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/support-app';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  name: {
    type: String,
    required: true
  },
  isAnonymous: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastActive: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  role: {
    type: String,
    default: 'admin'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Admin = mongoose.model('Admin', adminSchema);

// Rating Schema
const ratingSchema = new mongoose.Schema({
  rating: {
    type: Number,
    min: 1,
    max: 5,
    required: true
  },
  feedback: {
    type: String,
    default: ''
  },
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

// Message Schema
const chatMessageSchema = new mongoose.Schema({
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
});

const meetingLinksSchema = new mongoose.Schema({
  googleMeet: String,
  zoom: String,
  userGoogleMeet: String,
  userZoom: String
});

const messageSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
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
    enum: ['pending', 'in-chat', 'in-call', 'completed'],
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
  chatMessages: [chatMessageSchema],
  meetingLinks: meetingLinksSchema,
  callNotificationSent: {
    type: Boolean,
    default: false
  },
  userRating: ratingSchema,
  userCompletedAt: Date,
  completedBy: {
    type: String,
    enum: ['user', 'admin'],
    default: null
  }
});

const Message = mongoose.model('Message', messageSchema);

// Admin authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findById(decoded.userId);
    
    if (!admin) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    req.user = admin;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// User authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.type !== 'user') {
      return res.status(403).json({ error: 'Invalid token type' });
    }
    
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Update last active
    user.lastActive = new Date();
    await user.save();
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running!' });
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, isAnonymous } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({
      email,
      password: hashedPassword,
      name,
      isAnonymous: isAnonymous || false
    });

    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, email: user.email, type: 'user' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`User registered: ${email}`);
    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isAnonymous: user.isAnonymous
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// User Login
app.post('/api/auth/user-login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last active
    user.lastActive = new Date();
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email, type: 'user' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`User logged in: ${email}`);
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isAnonymous: user.isAnonymous
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Validate user token
app.post('/api/auth/validate-user', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.type !== 'user') {
      return res.status(403).json({ error: 'Invalid token type' });
    }
    
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    // Update last active
    user.lastActive = new Date();
    await user.save();

    res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      isAnonymous: user.isAnonymous
    });
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
});

// Create admin account
app.post('/api/auth/create-admin', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const admin = new Admin({
      email,
      password: hashedPassword,
      name
    });

    await admin.save();
    
    console.log(`Admin created: ${email}`);
    res.json({ message: 'Admin created successfully' });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

// Admin login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: admin._id, email: admin.email, type: 'admin' },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    console.log(`Admin logged in: ${email}`);
    res.json({
      token,
      user: {
        id: admin._id,
        email: admin.email,
        name: admin.name,
        role: admin.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Validate admin token
app.post('/api/auth/validate', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findById(decoded.userId);
    
    if (!admin) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    res.json({
      id: admin._id,
      email: admin.email,
      name: admin.name,
      role: admin.role
    });
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
});

// Get all messages (protected route - admin only)
app.get('/api/messages', authenticate, async (req, res) => {
  try {
    const messages = await Message.find().populate('userId', 'name email isAnonymous').sort({ timestamp: -1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get user's messages (authenticated user only)
app.get('/api/user/messages', authenticateUser, async (req, res) => {
  try {
    const messages = await Message.find({ userId: req.user._id }).sort({ timestamp: -1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching user messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get single message
app.get('/api/messages/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const message = await Message.findById(id).populate('userId', 'name email isAnonymous');
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    res.json(message);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch message' });
  }
});

// Create new message (authenticated users only)
app.post('/api/messages', authenticateUser, async (req, res) => {
  try {
    const { message } = req.body;
    
    const newMessage = new Message({
      userId: req.user._id,
      message,
      name: req.user.isAnonymous ? 'Anonymous' : req.user.name,
      isAnonymous: req.user.isAnonymous,
      chatMessages: [{
        sender: 'user',
        message: message,
        timestamp: new Date()
      }]
    });

    await newMessage.save();
    
    // Populate user info for admin dashboard
    await newMessage.populate('userId', 'name email isAnonymous');
    
    // Emit to admin dashboard in real-time
    io.emit('newMessage', newMessage);
    
    console.log(`New message from ${req.user.name}: ${message.substring(0, 50)}...`);
    
    res.json({ 
      success: true, 
      message: 'Message sent successfully!', 
      id: newMessage._id 
    });
  } catch (error) {
    console.error('Error creating message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Update message status (admin only)
app.patch('/api/messages/:id/status', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'in-chat', 'in-call', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const message = await Message.findByIdAndUpdate(
      id, 
      { 
        status: status,
        ...(status === 'completed' && { completedBy: 'admin' })
      }, 
      { new: true }
    );
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Emit status update to the user
    io.emit('messageStatusUpdate', { id: id, status: status });
    
    res.json({ success: true, message });
  } catch (error) {
    console.error('Error updating message status:', error);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Set meeting links (admin only)
app.patch('/api/messages/:id/meeting-links', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { googleMeet, zoom } = req.body;

    const message = await Message.findById(id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (!message.meetingLinks) {
      message.meetingLinks = {};
    }

    message.meetingLinks.googleMeet = googleMeet || '';
    message.meetingLinks.zoom = zoom || '';

    await message.save();
    
    // Emit meeting links update to user
    io.emit('meetingLinksUpdate', {
      messageId: id,
      meetingLinks: message.meetingLinks
    });
    
    res.json({ 
      success: true, 
      message: 'Meeting links updated successfully' 
    });
  } catch (error) {
    console.error('Error setting meeting links:', error);
    res.status(500).json({ error: 'Failed to set meeting links' });
  }
});

// User completes session endpoint
app.patch('/api/messages/:id/user-complete', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    
    const message = await Message.findById(id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Verify that the authenticated user owns this message
    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Update the message status to completed and mark who completed it
    message.status = 'completed';
    message.completedBy = 'user';
    message.userCompletedAt = new Date();
    
    await message.save();

    // Populate user info for the response
    await message.populate('userId', 'name email isAnonymous');

    // Emit to admin dashboard that user completed the session
    io.emit('userCompletedSession', {
      messageId: id,
      userName: message.name || 'Anonymous',
      message: message
    });

    console.log(`User ${req.user.name} completed session for message ${id}`);
    
    res.json({ 
      success: true, 
      message: 'Session completed successfully',
      messageStatus: message.status 
    });
  } catch (error) {
    console.error('Error completing user session:', error);
    res.status(500).json({ error: 'Failed to complete session' });
  }
});

// User rating endpoint
app.post('/api/messages/:id/rating', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { rating, feedback } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Valid rating (1-5) is required' });
    }

    const message = await Message.findById(id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Verify that the authenticated user owns this message
    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Add the rating
    message.userRating = {
      rating: rating,
      feedback: feedback || '',
      submittedAt: new Date()
    };

    await message.save();

    // Emit to admin dashboard
    io.emit('newRating', {
      messageId: id,
      rating: rating,
      feedback: feedback
    });

    console.log(`User ${req.user.name} rated session ${id} with ${rating} stars`);
    
    res.json({ 
      success: true, 
      message: 'Rating submitted successfully' 
    });
  } catch (error) {
    console.error('Error submitting rating:', error);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

// User sets their own meeting links endpoint
app.patch('/api/messages/:id/user-meeting-links', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { googleMeet, zoom } = req.body;

    const message = await Message.findById(id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Verify that the authenticated user owns this message
    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Update or create meeting links (merge with existing admin-set links)
    if (!message.meetingLinks) {
      message.meetingLinks = {};
    }

    // User can set their own links, but preserve admin links if they exist
    if (googleMeet) {
      message.meetingLinks.userGoogleMeet = googleMeet;
    }
    if (zoom) {
      message.meetingLinks.userZoom = zoom;
    }

    await message.save();
    
    res.json({ 
      success: true, 
      message: 'Meeting links updated successfully',
      meetingLinks: message.meetingLinks
    });
  } catch (error) {
    console.error('Error setting user meeting links:', error);
    res.status(500).json({ error: 'Failed to set meeting links' });
  }
});

// Create payment order
app.post('/api/create-payment-order', async (req, res) => {
  try {
    const { amount, messageId } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ success: false, error: 'Valid amount is required' });
    }

    const amountInPaise = Math.round(amount * 100);
    
    const order = await razorpay.orders.create({
      amount: amountInPaise,
      currency: 'INR',
      receipt: `receipt_${messageId}_${Date.now()}`,
      payment_capture: 1
    });

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error('Payment order creation error:', error);
    res.status(500).json({ success: false, error: 'Failed to create payment order' });
  }
});

// Verify payment
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, messageId, amount } = req.body;

    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
                                    .update(body.toString())
                                    .digest('hex');

    if (expectedSignature === razorpay_signature) {
      // Update message with payment info
      await Message.findByIdAndUpdate(messageId, {
        paymentStatus: 'paid',
        paymentId: razorpay_payment_id,
        amountPaid: amount / 100, // Convert from paise to rupees
        paidAt: new Date()
      });

      // Emit payment received event to admin
      io.emit('paymentReceived', {
        messageId: messageId,
        amount: amount / 100,
        paymentId: razorpay_payment_id
      });

      console.log(`Payment verified for message ${messageId}: ₹${amount / 100}`);

      res.json({ success: true, message: 'Payment verified successfully' });
    } else {
      res.status(400).json({ success: false, error: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ success: false, error: 'Payment verification failed' });
  }
});

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  // Admin joins admin room
  socket.on('join-admin', () => {
    socket.join('admin');
    console.log(`Admin joined: ${socket.id}`);
  });

  // User joins specific message room
  socket.on('join-message-room', (messageId) => {
    socket.join(`message-${messageId}`);
    console.log(`User joined message room: ${messageId}`);
  });

  // User joins user-specific room
  socket.on('join-user-room', (userId) => {
    socket.join(`user-${userId}`);
    console.log(`User joined user room: ${userId}`);
  });

  // Handle chat messages
  socket.on('send-chat-message', async (data) => {
    const { messageId, message, sender } = data;
    
    try {
      const chatMessage = {
        sender: sender,
        message: message,
        timestamp: new Date()
      };

      // Add message to database
      await Message.findByIdAndUpdate(messageId, {
        $push: { chatMessages: chatMessage }
      });

      // Broadcast to all clients in the message room
      io.to(`message-${messageId}`).emit('newChatMessage', {
        messageId: messageId,
        chatMessage: chatMessage
      });

      // Also emit to admin room
      io.to('admin').emit('newChatMessage', {
        messageId: messageId,
        chatMessage: chatMessage
      });

      console.log(`Chat message sent in ${messageId}: ${message.substring(0, 50)}...`);
    } catch (error) {
      console.error('Error handling chat message:', error);
    }
  });

  // Handle user completing session
  socket.on('user-completed-session', (data) => {
    const { messageId, userName } = data;
    
    // Emit to admin dashboard
    io.to('admin').emit('userCompletedSession', {
      messageId: messageId,
      userName: userName
    });

    console.log(`User ${userName} completed session ${messageId}`);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Admin Dashboard: http://localhost:${PORT}/?admin`);
  console.log(`User Interface: http://localhost:${PORT}/`);
});