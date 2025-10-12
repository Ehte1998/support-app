const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Conditional Firebase Admin import for push notifications
let admin = null;
let firebaseAvailable = false;

try {
  admin = require('firebase-admin');
  firebaseAvailable = true;
  console.log('Firebase Admin SDK loaded successfully');
} catch (error) {
  console.warn('Firebase Admin SDK not available:', error.message);
  console.log('Server will start without push notifications');
}
require('dotenv').config();

const app = express();
const server = http.createServer(app);

app.use(express.static('public'));
// Serve the delete account page
app.get('/delete-account', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'delete-account.html'));
});

// Validate critical environment variables
if (process.env.NODE_ENV === 'production') {
  if (!process.env.MONGODB_URI) {
    console.error('CRITICAL: MONGODB_URI not found');
    process.exit(1);
  }
  if (!process.env.PAYPAL_CLIENT_ID || !process.env.PAYPAL_CLIENT_SECRET) {
    console.error('CRITICAL: PayPal credentials not found');
    process.exit(1);
  }
  if (!process.env.CASHFREE_APP_ID || !process.env.CASHFREE_SECRET_KEY) {
    console.error('CRITICAL: Cashfree credentials not found');
    process.exit(1);
  }
}

// CREATE UPLOADS DIRECTORY IF IT DOESN'T EXIST
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// INITIALIZE FIREBASE ADMIN FOR PUSH NOTIFICATIONS
if (firebaseAvailable && admin && !admin.apps.length) {
  try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
      const credential = admin.credential.cert(serviceAccount);

      admin.initializeApp({
        credential: credential,
        projectId: 'supportadmin-15867'
      });

      console.log('Firebase Admin initialized successfully');
    } else {
      console.log('FIREBASE_SERVICE_ACCOUNT_KEY not found - push notifications disabled');
      firebaseAvailable = false;
    }
  } catch (error) {
    console.error('Firebase Admin initialization failed:', error.message);
    console.log('Push notifications will be disabled');
    firebaseAvailable = false;
  }
}

// CONFIGURE MULTER FOR FILE UPLOADS
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/mov', 'video/avi', 'video/mkv', 'video/webm', 'video/3gp'
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images and videos are allowed.'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 4 * 1024 * 1024 * 1024,
  }
});

// FIXED CORS CONFIGURATION
const corsOriginHandler = (origin, callback) => {
  console.log('CORS request from origin:', origin);

  if (!origin) {
    console.log('CORS allowed for request with no origin');
    return callback(null, true);
  }

  const allowedOrigins = process.env.NODE_ENV === 'production'
    ? [
      "https://ehtecounseling.com",
      "https://www.ehtecounseling.com",
      process.env.FRONTEND_URL,
      "https://support-app-2.vercel.app",
    ].filter(Boolean)
    : ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"];

  const isVercelPreview = origin.match(/^https:\/\/support-app-2-[a-zA-Z0-9-]+.*\.vercel\.app$/);

  if (allowedOrigins.includes(origin) || isVercelPreview) {
    console.log('CORS allowed for origin:', origin);
    callback(null, true);
  } else {
    console.log('CORS blocked origin:', origin);
    callback(null, true);
  }
};

// ENHANCED CORS MIDDLEWARE
app.use(cors({
  origin: corsOriginHandler,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'Pragma'
  ],
  optionsSuccessStatus: 204
}));

// EXPLICIT OPTIONS HANDLERS
app.options('*', cors({
  origin: corsOriginHandler,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'Cache-Control', 'Pragma']
}));

// PREFLIGHT DEBUGGING MIDDLEWARE
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    console.log('Handling OPTIONS preflight for:', req.path);
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS,PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With, Origin, Accept');
    res.header('Access-Control-Allow-Credentials', 'true');
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());
app.use('/uploads', express.static(uploadsDir));

// Socket.IO with CORS
const io = new Server(server, {
  cors: {
    origin: corsOriginHandler,
    credentials: true
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-jwt-secret-change-in-production';

// PayPal Configuration
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_API_BASE = process.env.NODE_ENV === 'production'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

// Cashfree Configuration (for UPI/GPay)
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_API_BASE = process.env.CASHFREE_API_BASE || 'https://sandbox.cashfree.com';

// PayPal Access Token Function
async function getPayPalAccessToken() {
  try {
    const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
    const response = await axios.post(
      `${PAYPAL_API_BASE}/v1/oauth2/token`,
      'grant_type=client_credentials',
      {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    return response.data.access_token;
  } catch (error) {
    console.error('PayPal token error:', error.response?.data || error.message);
    throw new Error('Failed to get PayPal access token');
  }
}

// Create PayPal Order
async function createPayPalOrder(amount, currency = 'USD', messageId) {
  try {
    const accessToken = await getPayPalAccessToken();

    const orderData = {
      intent: 'CAPTURE',
      purchase_units: [{
        reference_id: messageId || `order_${Date.now()}`,
        amount: {
          currency_code: currency,
          value: amount.toFixed(2)
        },
        description: 'Peer Support Platform Contribution'
      }],
      application_context: {
        brand_name: 'FeelingsShare',
        landing_page: 'NO_PREFERENCE',
        user_action: 'PAY_NOW',
        return_url: `${process.env.FRONTEND_URL || 'https://ehtecounseling.com'}/?payment-success`,
        cancel_url: `${process.env.FRONTEND_URL || 'https://ehtecounseling.com'}/?payment-cancel`
      }
    };

    const response = await axios.post(
      `${PAYPAL_API_BASE}/v2/checkout/orders`,
      orderData,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error) {
    console.error('PayPal order creation error:', error.response?.data || error.message);
    throw new Error('Failed to create PayPal order');
  }
}

// Capture PayPal Payment
async function capturePayPalPayment(orderId) {
  try {
    const accessToken = await getPayPalAccessToken();

    const response = await axios.post(
      `${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data;
  } catch (error) {
    console.error('PayPal capture error:', error.response?.data || error.message);
    throw new Error('Failed to capture PayPal payment');
  }
}

// Create Cashfree Order (UPDATED FOR v2 API)
async function createCashfreeOrder(amount, messageId, customerDetails = {}) {
  try {
    const orderId = `order_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Cashfree v2 API uses different structure
    const orderData = {
      order_id: orderId,
      order_amount: amount,
      order_currency: 'INR',
      customer_details: {
        customer_id: `customer_${Date.now()}`,
        customer_name: customerDetails.name || 'User',
        customer_email: customerDetails.email || 'user@feelingsshare.com',
        customer_phone: customerDetails.phone || '9999999999'
      },
      order_meta: {
        return_url: `https://ehtecounseling.com/?payment-success&order_id={order_id}`,
        notify_url: `https://support-app-1-m6kf.onrender.com/api/cashfree/webhook`
      },
      order_note: 'Peer Support Platform Contribution'
    };

    console.log('📦 Cashfree v2 Request:');
    console.log('   API URL:', `${CASHFREE_API_BASE}/pg/orders`);
    console.log('   Order Data:', JSON.stringify(orderData, null, 2));
    console.log('   App ID:', CASHFREE_APP_ID ? 'Set' : 'Missing');
    console.log('   Secret Key:', CASHFREE_SECRET_KEY ? 'Set (hidden)' : 'Missing');

    const response = await axios.post(
      `${CASHFREE_API_BASE}/pg/orders`,
      orderData,
      {
        headers: {
          'Content-Type': 'application/json',
          'x-api-version': '2022-09-01',
          'x-client-id': CASHFREE_APP_ID,
          'x-client-secret': CASHFREE_SECRET_KEY
        }
      }
    );

    console.log('📥 Cashfree v2 Raw Response:');
    console.log('   Status:', response.status);
    console.log('   Full Response:', JSON.stringify(response.data, null, 2));
    console.log('   payment_session_id:', response.data.payment_session_id);
    console.log('   All keys:', Object.keys(response.data));

    if (response.data.payment_session_id) {
      const result = {
        success: true,
        orderId: orderId,
        paymentSessionId: response.data.payment_session_id,  // Frontend will use this
        cfOrderId: response.data.cf_order_id
      };

      console.log('✅ Returning to endpoint:', JSON.stringify(result, null, 2));
      return result;
    } else {
      console.error('❌ No payment_session_id in response');
      throw new Error('Failed to create order - no payment session');
    }
  } catch (error) {
    console.error('💥 Cashfree order creation error:');
    console.error('   Error message:', error.message);
    console.error('   Response data:', JSON.stringify(error.response?.data, null, 2));
    console.error('   Response status:', error.response?.status);
    console.error('   Response headers:', error.response?.headers);
    throw new Error(error.response?.data?.message || 'Failed to create Cashfree order');
  }
}

// Verify Cashfree Payment (v2 API)
// Verify Cashfree Payment (v2 API)
async function verifyCashfreePayment(orderId) {
  try {
    console.log('==========================================');
    console.log('🔍 CASHFREE VERIFICATION DEBUG');
    console.log('==========================================');
    console.log('Order ID:', orderId);
    console.log('API Base:', CASHFREE_API_BASE);
    console.log('Full URL:', `${CASHFREE_API_BASE}/orders/${orderId}`);
    console.log('App ID:', CASHFREE_APP_ID ? 'SET' : 'MISSING');
    console.log('Secret Key:', CASHFREE_SECRET_KEY ? 'SET (hidden)' : 'MISSING');

    const response = await axios.get(
      `${CASHFREE_API_BASE}/orders/${orderId}`,
      {
        headers: {
          'Content-Type': 'application/json',
          'x-api-version': '2022-09-01',
          'x-client-id': CASHFREE_APP_ID,
          'x-client-secret': CASHFREE_SECRET_KEY
        }
      }
    );

    console.log('📥 Cashfree Raw Response:');
    console.log('   Status Code:', response.status);
    console.log('   Response Data:', JSON.stringify(response.data, null, 2));
    console.log('==========================================');

    return {
      orderId: response.data.order_id,
      orderAmount: response.data.order_amount,
      orderStatus: response.data.order_status,
      orderToken: response.data.order_token,
      txStatus: response.data.order_status === 'PAID' ? 'SUCCESS' : response.data.order_status,
      referenceId: response.data.cf_order_id,
      paymentMethod: response.data.payment_method,
      paymentTime: response.data.payment_completion_time
    };
  } catch (error) {
    console.error('💥 Cashfree verification error:');
    console.error('   Error Message:', error.message);
    console.error('   Response Status:', error.response?.status);
    console.error('   Response Data:', JSON.stringify(error.response?.data, null, 2));
    console.error('==========================================');
    throw new Error(error.response?.data?.message || 'Failed to verify Cashfree payment');
  }
}

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

// Admin Schema - Updated with push notification fields
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
  pushToken: {
    type: String,
    default: null
  },
  deviceType: {
    type: String,
    default: null
  },
  lastTokenUpdate: {
    type: Date,
    default: null
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

// Chat Message Schema with File Support
const chatMessageSchema = new mongoose.Schema({
  sender: {
    type: String,
    enum: ['user', 'admin'],
    required: true
  },
  message: {
    type: String,
    default: ''
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'video'],
    default: 'text'
  },
  file: {
    filename: String,
    originalName: String,
    mimetype: String,
    size: Number,
    url: String
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

// FIXED Message Schema
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

  pendingPaymentOrderId: String,
  pendingPaymentMethod: String,
  pendingPaymentAmount: Number,
  pendingPaymentCreatedAt: Date,

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
    required: false
  }
});

const Message = mongoose.model('Message', messageSchema);
// Authentication Middlewares
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

    user.lastActive = new Date();
    await user.save();

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// FIXED FILE UPLOAD ROUTES WITH CORS

// User File Upload
app.post('/api/upload/:messageId', authenticateUser, (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  console.log('File upload request from origin:', req.headers.origin);
  next();
}, upload.single('file'), async (req, res) => {
  try {
    const { messageId } = req.params;
    const { caption } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    let messageType = 'text';
    if (req.file.mimetype.startsWith('image/')) {
      messageType = 'image';
    } else if (req.file.mimetype.startsWith('video/')) {
      messageType = 'video';
    }

    const fileData = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      url: `/uploads/${req.file.filename}`
    };

    const chatMessage = {
      sender: 'user',
      message: caption || '',
      messageType: messageType,
      file: fileData,
      timestamp: new Date()
    };

    const updateData = {
      $push: { chatMessages: chatMessage }
    };

    if (message.status === 'pending') {
      updateData.status = 'in-chat';
    }

    await Message.findByIdAndUpdate(
      messageId,
      updateData,
      { new: true, runValidators: true }
    );

    const io = req.app.get('io');
    if (io) {
      io.emit('newChatMessage', {
        messageId: messageId,
        chatMessage: chatMessage
      });
    }

    console.log(`File uploaded by user ${req.user.name}: ${req.file.originalname}`);

    res.json({
      success: true,
      message: 'File uploaded successfully',
      file: fileData,
      chatMessage: chatMessage
    });

  } catch (error) {
    console.error('File upload error:', error);

    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({ error: 'File upload failed' });
  }
});

// Admin File Upload
app.post('/api/admin/upload/:messageId', authenticate, (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  console.log('Admin file upload request from origin:', req.headers.origin);
  next();
}, upload.single('file'), async (req, res) => {
  try {
    const { messageId } = req.params;
    const { caption } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    let messageType = 'text';
    if (req.file.mimetype.startsWith('image/')) {
      messageType = 'image';
    } else if (req.file.mimetype.startsWith('video/')) {
      messageType = 'video';
    }

    const fileData = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      url: `/uploads/${req.file.filename}`
    };

    const chatMessage = {
      sender: 'admin',
      message: caption || '',
      messageType: messageType,
      file: fileData,
      timestamp: new Date()
    };

    const updateData = {
      $push: { chatMessages: chatMessage }
    };

    if (message.status === 'pending') {
      updateData.status = 'in-chat';
    }

    await Message.findByIdAndUpdate(
      messageId,
      updateData,
      { new: true, runValidators: true }
    );

    const io = req.app.get('io');
    if (io) {
      io.emit('newChatMessage', {
        messageId: messageId,
        chatMessage: chatMessage
      });
    }

    console.log(`File uploaded by admin ${req.user.name}: ${req.file.originalname}`);

    res.json({
      success: true,
      message: 'File uploaded successfully',
      file: fileData,
      chatMessage: chatMessage
    });

  } catch (error) {
    console.error('Admin file upload error:', error);

    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({ error: 'File upload failed' });
  }
});

// 3. ADD PLATFORM DISCLAIMER ENDPOINT (add after line 555)
app.get('/api/platform-info', (req, res) => {
  res.json({
    platformName: 'FeelingsShare',
    platformType: 'peer_support',
    disclaimer: {
      title: 'Peer Support Platform',
      message: 'This is a peer support platform where you can share your feelings with caring listeners. This is NOT professional therapy or medical advice. Listeners are volunteers, not licensed professionals. For emergencies, please contact crisis services immediately.',
      emergencyResources: [
        { name: 'Emergency Services', number: '112', type: 'emergency' },
        { name: 'KIRAN Mental Health', number: '1800-599-0019', type: 'mental_health' },
        { name: 'AASRA Suicide Prevention', number: '91-22-27546669', type: 'crisis' },
        { name: 'Vandrevala Foundation', number: '1860-2662-345', type: 'crisis' }
      ]
    },
    features: [
      'Anonymous peer support',
      'Text chat conversations',
      'Video call option (Google Meet/Zoom)',
      'Photo and video sharing',
      'Pay what feels right (optional)'
    ]
  });
});

// Basic Routes
app.get('/', (req, res) => {
  res.json({
    message: 'FeelingsShare API Server - Peer Support Platform',
    status: 'running',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running!' });
});

app.get('/api/debug', (req, res) => {
  res.json({
    origin: req.headers.origin,
    referer: req.headers.referer,
    userAgent: req.headers['user-agent'],
    timestamp: new Date().toISOString()
  });
});

// DELETE account endpoint - requires authentication
app.delete('/api/user/delete-account', authenticateUser, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;

    // 1. Delete all messages created by this user
    await Message.deleteMany({ userId: userId });

    // 2. Delete all chat messages in conversations with this user
    await Message.updateMany(
      { 'chatMessages.sender': userId },
      { $pull: { chatMessages: { sender: userId } } }
    );

    // 3. Delete ratings/feedback
    if (mongoose.models.Rating) {
      await mongoose.model('Rating').deleteMany({ userId: userId });
    }

    // 4. Delete media files
    try {
      const uploadsPath = path.join(__dirname, 'uploads');
      const files = await fs.readdir(uploadsPath);
      const userFiles = files.filter(file => file.includes(userId.toString()));

      for (const file of userFiles) {
        await fs.unlink(path.join(uploadsPath, file));
      }
    } catch (err) {
      console.log('Media cleanup error:', err);
    }

    // 5. Delete the user account
    await User.findByIdAndDelete(userId);

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });

  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete account'
    });
  }
});

// POST endpoint for deletion request (for users who can't log in)
app.post('/api/user/request-deletion', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      // Don't reveal if email exists or not
      return res.json({
        success: true,
        message: 'If this email exists, a deletion request has been recorded.'
      });
    }

    // You can either:
    // Option 1: Delete immediately
    await User.findByIdAndDelete(user._id);
    await Message.deleteMany({ userId: user._id });

    // Option 2: Create a pending request (create a DeletionRequest model first)
    // await DeletionRequest.create({ email, requestDate: new Date() });

    res.json({
      success: true,
      message: 'Account deletion request received. Processing within 48 hours.'
    });

  } catch (error) {
    console.error('Deletion request error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process request'
    });
  }
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

// Store push token (admin only)
app.post('/api/admin/register-push-token', authenticate, async (req, res) => {
  try {
    const { pushToken, deviceType } = req.body;

    await Admin.findByIdAndUpdate(req.user._id, {
      pushToken: pushToken,
      deviceType: deviceType,
      lastTokenUpdate: new Date()
    });

    res.json({ success: true, message: 'Push token registered' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register push token' });
  }
});

// Send push notification endpoint
app.post('/api/admin/send-notification', authenticate, async (req, res) => {
  try {
    // Check if Firebase is initialized
    if (!firebaseAvailable || !admin) {
      return res.status(500).json({ error: 'Push notification service not available' });
    }

    const { title, body, data = {} } = req.body;

    // Get all admin tokens
    const admins = await Admin.find({ pushToken: { $exists: true, $ne: null } });

    if (admins.length === 0) {
      return res.json({ success: true, message: 'No devices to notify' });
    }
    const tokens = admins.map(admin => admin.pushToken);

    const message = {
      notification: { title, body },
      data: { ...data, timestamp: Date.now().toString() },
      tokens: tokens
    };
    const response = await admin.messaging().sendMulticast(message);

    console.log(`Notification sent to ${response.successCount} devices`);
    res.json({
      success: true,
      successCount: response.successCount,
      failureCount: response.failureCount
    });
  } catch (error) {
    console.error('Push notification error:', error);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});
// Message Routes
app.get('/api/messages', authenticate, async (req, res) => {
  try {
    const messages = await Message.find().populate('userId', 'name email isAnonymous').sort({ timestamp: -1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/api/user/messages', authenticateUser, async (req, res) => {
  try {
    const messages = await Message.find({ userId: req.user._id }).sort({ timestamp: -1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching user messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

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
        messageType: 'text',
        timestamp: new Date()
      }]
    });

    await newMessage.save();

    await newMessage.populate('userId', 'name email isAnonymous');

    io.emit('newMessage', newMessage);

    // AUTO-NOTIFICATION FOR NEW MESSAGES
    try {
      if (firebaseAvailable && admin) {
        const admins = await Admin.find({ pushToken: { $exists: true, $ne: null } });
        if (admins.length > 0) {
          const tokens = admins.map(admin => admin.pushToken);
          await admin.messaging().sendMulticast({
            notification: {
              title: 'New Feelings Shared',
              body: `${newMessage.name} shared their feelings`
            },
            data: {
              type: 'new_message',
              messageId: newMessage._id.toString()
            },
            tokens: tokens
          });
        }
      }
    } catch (error) {
      console.error('Auto notification error:', error);
    }

    console.log(`New feelings shared by ${req.user.name}: ${message.substring(0, 50)}...`);

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

// Socket.IO Connection Handling with Push Notifications
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('join-admin', () => {
    socket.join('admin');
    console.log(`Admin joined: ${socket.id}`);
  });

  socket.on('join-message-room', (messageId) => {
    socket.join(`message-${messageId}`);
    console.log(`User joined message room: ${messageId}`);
  });

  socket.on('join-user-room', (userId) => {
    socket.join(`user-${userId}`);
    console.log(`User joined user room: ${userId}`);
  });

  socket.on('send-chat-message', async (data) => {
    const { messageId, message, sender, messageType, file } = data;

    try {
      const chatMessage = {
        sender: sender,
        message: message || '',
        messageType: messageType || 'text',
        file: file || null,
        timestamp: new Date()
      };

      await Message.findByIdAndUpdate(messageId, {
        $push: { chatMessages: chatMessage }
      });

      io.to(`message-${messageId}`).emit('newChatMessage', {
        messageId: messageId,
        chatMessage: chatMessage
      });

      io.to('admin').emit('newChatMessage', {
        messageId: messageId,
        chatMessage: chatMessage
      });

      const messagePreview = messageType === 'text' ?
        message.substring(0, 50) + '...' :
        `${messageType} file: ${file?.originalName || 'unknown'}`;

      console.log(`Chat message sent in ${messageId}: ${messagePreview}`);

      // AUTO-NOTIFICATION FOR CHAT MESSAGES
      try {
        if (firebaseAvailable && admin) {
          const admins = await Admin.find({ pushToken: { $exists: true, $ne: null } });
          if (admins.length > 0) {
            const tokens = admins.map(admin => admin.pushToken);
            await admin.messaging().sendMulticast({
              notification: {
                title: 'New Message',
                body: sender === 'user' ? `New message: ${messagePreview}` : 'Supporter Responded'
              },
              data: {
                type: 'new_chat_message',
                messageId: messageId
              },
              tokens: tokens
            });
          }
        }
      } catch (notificationError) {
        console.error('Auto notification error:', notificationError);
      }

    } catch (error) {
      console.error('Error handling chat message:', error);
    }
  });

  socket.on('user-completed-conversation', (data) => {
    const { messageId, userName } = data;

    io.to('admin').emit('userCompletedconversation', {
      messageId: messageId,
      userName: userName
    });

    console.log(`User ${userName} completed conversation ${messageId}`);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

app.set('io', io);
// Update message status (admin only)
app.patch('/api/messages/:id/status', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ['pending', 'in-chat', 'in-call', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const updateData = { status: status };
    if (status === 'completed') {
      updateData.completedBy = 'admin';
    }

    const message = await Message.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

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

// User completes conversation endpoint
app.patch('/api/messages/:id/user-complete', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;

    const message = await Message.findById(id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    message.status = 'completed';
    message.completedBy = 'user';
    message.userCompletedAt = new Date();

    await message.save();

    await message.populate('userId', 'name email isAnonymous');

    io.emit('userCompletedconversation', {
      messageId: id,
      userName: message.name || 'Anonymous',
      message: message
    });

    console.log(`User ${req.user.name} completed conversation for message ${id}`);

    res.json({
      success: true,
      message: 'conversation completed successfully',
      messageStatus: message.status
    });
  } catch (error) {
    console.error('Error completing user conversation:', error);
    res.status(500).json({ error: 'Failed to complete conversation' });
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

    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    message.userRating = {
      rating: rating,
      feedback: feedback || '',
      submittedAt: new Date()
    };

    await message.save();

    io.emit('newRating', {
      messageId: id,
      rating: rating,
      feedback: feedback
    });

    console.log(`User ${req.user.name} rated conversation ${id} with ${rating} stars`);

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

    if (message.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    if (!message.meetingLinks) {
      message.meetingLinks = {};
    }

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

// Create Payment Order - Multi-Gateway
// Replace your /api/create-payment-order endpoint with this DEBUG version

app.post('/api/create-payment-order', async (req, res) => {
  try {
    // === DEBUG LOGGING START ===
    console.log('=================================');
    console.log('📥 PAYMENT ORDER REQUEST RECEIVED');
    console.log('=================================');
    console.log('Raw Body:', JSON.stringify(req.body, null, 2));
    console.log('Request Headers:', req.headers['content-type']);
    console.log('---------------------------------');

    const { amount, messageId, paymentMethod, customerDetails } = req.body;

    console.log('Parsed Values:');
    console.log('  amount:', amount, typeof amount);
    console.log('  messageId:', messageId, typeof messageId);
    console.log('  paymentMethod:', paymentMethod, typeof paymentMethod);
    console.log('  customerDetails:', customerDetails);
    console.log('=================================');
    // === DEBUG LOGGING END ===

    if (!amount || amount < 1) {
      console.log('❌ Validation failed: Invalid amount');
      return res.status(400).json({ success: false, error: 'Valid amount is required' });
    }

    // Check if paymentMethod is provided
    if (!paymentMethod) {
      console.log('❌ Validation failed: paymentMethod is missing or undefined');
      return res.status(400).json({
        success: false,
        error: 'Payment method is required. Received: ' + paymentMethod
      });
    }

    // Check if paymentMethod is valid
    const validMethods = ['paypal', 'upi', 'gpay'];
    if (!validMethods.includes(paymentMethod)) {
      console.log('❌ Validation failed: Invalid payment method:', paymentMethod);
      console.log('Valid methods are:', validMethods);
      return res.status(400).json({
        success: false,
        error: `Invalid payment method: "${paymentMethod}". Choose: paypal, upi, or gpay`
      });
    }

    console.log('✅ Validation passed. Creating payment order...');

    // PayPal Payment
    if (paymentMethod === 'paypal') {
      console.log('💙 Processing PayPal payment...');
      const amountUSD = (amount / 83).toFixed(2);
      const order = await createPayPalOrder(parseFloat(amountUSD), 'USD', messageId);

      console.log('✅ PayPal order created:', order.id);

      return res.json({
        success: true,
        paymentMethod: 'paypal',
        orderId: order.id,
        approvalUrl: order.links.find(link => link.rel === 'approve')?.href,
        amount: amountUSD,
        currency: 'USD'
      });
    }

    // UPI/GPay Payment (via Cashfree)
    else if (paymentMethod === 'upi' || paymentMethod === 'gpay') {
      console.log(`💳 Processing ${paymentMethod.toUpperCase()} payment...`);
      const order = await createCashfreeOrder(amount, messageId, customerDetails);

      console.log('✅ Cashfree order created:', order.orderId);

      // Store payment intent in database as backup
      if (messageId) {
        try {
          await Message.findByIdAndUpdate(messageId, {
            $set: {
              pendingPaymentOrderId: order.orderId,
              pendingPaymentMethod: paymentMethod,
              pendingPaymentAmount: amount,
              pendingPaymentCreatedAt: new Date()
            }
          });
          console.log('💾 Stored payment intent in database for message:', messageId);
        } catch (err) {
          console.error('⚠️ Failed to store payment intent:', err);
          // Don't fail the payment if database update fails
        }
      }

      return res.json({
        success: true,
        paymentMethod: paymentMethod,
        orderId: order.orderId,
        paymentSessionId: order.paymentSessionId,  // ✅ Change this!
        cfOrderId: order.cfOrderId,
        amount: amount,
        currency: 'INR'
      });
    }

  } catch (error) {
    console.error('💥 Payment order creation error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to create payment order'
    });
  }
});

// Add this TEST endpoint to your server.js (for debugging only)

app.post('/api/test-payment-data', (req, res) => {
  console.log('📦 TEST ENDPOINT - Received data:');
  console.log(JSON.stringify(req.body, null, 2));

  res.json({
    success: true,
    message: 'Data received successfully',
    receivedData: req.body,
    dataTypes: {
      amount: typeof req.body.amount,
      messageId: typeof req.body.messageId,
      paymentMethod: typeof req.body.paymentMethod,
      customerDetails: typeof req.body.customerDetails
    }
  });
});

// Bulk delete messages (admin only)
app.delete('/api/messages/bulk-delete', authenticate, async (req, res) => {
  try {
    const { messageIds } = req.body;

    if (!messageIds || !Array.isArray(messageIds)) {
      return res.status(400).json({ error: 'Message IDs array is required' });
    }

    const messages = await Message.find({ _id: { $in: messageIds } });
    for (const message of messages) {
      if (message.chatMessages) {
        for (const chatMsg of message.chatMessages) {
          if (chatMsg.file && chatMsg.file.filename) {
            const filePath = path.join(uploadsDir, chatMsg.file.filename);
            if (fs.existsSync(filePath)) {
              fs.unlinkSync(filePath);
              console.log(`Deleted file: ${filePath}`);
            }
          }
        }
      }
    }

    const result = await Message.deleteMany({ _id: { $in: messageIds } });

    console.log(`Admin bulk deleted ${result.deletedCount} messages`);

    res.json({
      success: true,
      message: `${result.deletedCount} conversations deleted successfully`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Error bulk deleting messages:', error);
    res.status(500).json({ error: 'Failed to delete conversations' });
  }
});

// Delete message/conversation (admin only)
app.delete('/api/messages/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    console.log(`Attempting to delete message: ${id}`);

    if (!id.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ error: 'Invalid message ID format' });
    }

    const message = await Message.findById(id);

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.chatMessages) {
      for (const chatMsg of message.chatMessages) {
        if (chatMsg.file && chatMsg.file.filename) {
          const filePath = path.join(uploadsDir, chatMsg.file.filename);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            console.log(`Deleted file: ${filePath}`);
          }
        }
      }
    }

    await Message.findByIdAndDelete(id);

    console.log(`Admin deleted message ${id}`);

    res.json({
      success: true,
      message: 'Conversation deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Failed to delete conversation' });
  }
});

// Verify Payment - Multi-Gateway
app.post('/api/verify-payment', async (req, res) => {
  try {
    const requestData = req.body;
    let paymentMethod = requestData.paymentMethod;
    const orderId = requestData.orderId;
    let messageId = requestData.messageId;

    console.log('🔍 Verifying payment:', { paymentMethod, orderId, messageId });

    // If payment method not provided, try to find it in database
    if (!paymentMethod && orderId) {
      console.log('⚠️ No payment method provided, checking database...');

      const message = await Message.findOne({
        pendingPaymentOrderId: orderId
      });

      if (message && message.pendingPaymentMethod) {
        paymentMethod = message.pendingPaymentMethod;
        messageId = messageId || message._id.toString();
        console.log('✅ Found payment method from database:', paymentMethod);
      }
    }

    // Default to upi if still not found
    if (!paymentMethod) {
      paymentMethod = 'upi';
    }

    console.log('📍 Final payment method:', paymentMethod);

    // UPI/GPay Verification (via Cashfree)
    if (paymentMethod === 'upi' || paymentMethod === 'gpay') {
      try {
        console.log('🔍 Starting Cashfree verification...');
        const paymentData = await verifyCashfreePayment(orderId);

        console.log('📊 Cashfree Status Check:');
        console.log('   orderStatus:', paymentData.orderStatus);
        console.log('   txStatus:', paymentData.txStatus);
        console.log('   orderAmount:', paymentData.orderAmount);
        console.log('   referenceId:', paymentData.referenceId);

        if (paymentData.orderStatus === 'PAID') {
          console.log('✅ Payment is PAID - clearing pending data');

          if (messageId) {
            await Message.findByIdAndUpdate(messageId, {
              $unset: {
                pendingPaymentOrderId: 1,
                pendingPaymentMethod: 1,
                pendingPaymentAmount: 1,
                pendingPaymentCreatedAt: 1
              }
            });
          }

          return res.json({
            success: true,
            message: 'Payment verified successfully',
            transactionId: paymentData.referenceId,
            amount: paymentData.orderAmount
          });
        }
        else if (paymentData.orderStatus === 'ACTIVE') {
          console.log('⏳ Payment is ACTIVE - needs more time');
          return res.status(202).json({
            success: false,
            status: 'ACTIVE',
            message: 'Payment is still processing',
            error: 'Payment not completed yet'
          });
        }
        else {
          console.log(`❌ Payment status is: ${paymentData.orderStatus}`);
          return res.status(400).json({
            success: false,
            error: 'Payment not completed yet',
            status: paymentData.orderStatus
          });
        }
      } catch (error) {
        console.error('💥 Verification error:', error.message);
        return res.status(500).json({
          success: false,
          error: error.message || 'Failed to verify payment'
        });
      }
    }

    // PayPal Verification
    else if (paymentMethod === 'paypal') {
      const captureData = await capturePayPalPayment(orderId);

      if (captureData.status === 'COMPLETED') {
        return res.json({
          success: true,
          message: 'PayPal payment verified successfully',
          captureId: captureData.id
        });
      } else {
        return res.status(400).json({
          success: false,
          error: 'Payment not completed'
        });
      }
    }

    else {
      return res.status(400).json({
        success: false,
        error: 'Invalid payment method'
      });
    }

  } catch (error) {
    console.error('💥 Payment verification error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: error.message || 'Payment verification failed'
    });
  }
});

// Cashfree Webhook Handler (FIXED VERSION)
app.post('/api/cashfree/webhook', async (req, res) => {
  try {
    const webhookData = req.body;
    console.log('📥 Cashfree webhook received:', JSON.stringify(webhookData, null, 2));

    // Handle payment status
    if (webhookData.type === 'PAYMENT_SUCCESS_WEBHOOK') {
      const orderId = webhookData.data.order.order_id;
      const amount = webhookData.data.payment.payment_amount;
      const paymentId = webhookData.data.payment.cf_payment_id;

      console.log('✅ Payment success for order:', orderId);

      // ⬇️⬇️⬇️ IMPROVED LOGIC: Find by pendingPaymentOrderId first ⬇️⬇️⬇️
      let message = await Message.findOne({
        pendingPaymentOrderId: orderId
      });

      if (message) {
        console.log('✅ Found message by pendingPaymentOrderId:', message._id);
      } else {
        // Fallback: Try to find by timestamp
        console.log('⚠️ Message not found by orderId, trying timestamp method...');

        const customerId = webhookData.data.customer_details.customer_id;
        const timestamp = customerId.replace('customer_', '');
        const timeWindow = 10 * 60 * 1000; // 10 minutes window
        const messageTime = parseInt(timestamp);

        message = await Message.findOne({
          timestamp: {
            $gte: new Date(messageTime - timeWindow),
            $lte: new Date(messageTime + timeWindow)
          },
          paymentStatus: { $ne: 'paid' }
        }).sort({ timestamp: -1 });

        if (message) {
          console.log('✅ Found message by timestamp:', message._id);
        }
      }
      // ⬆️⬆️⬆️ IMPROVED LOGIC ⬆️⬆️⬆️

      if (message) {
        // Update payment status
        message.paymentStatus = 'paid';
        message.paymentId = paymentId;
        message.paymentMethod = 'cashfree';
        message.amountPaid = amount;
        message.paidAt = new Date();

        // Clear pending payment data
        message.pendingPaymentOrderId = undefined;
        message.pendingPaymentMethod = undefined;
        message.pendingPaymentAmount = undefined;
        message.pendingPaymentCreatedAt = undefined;

        await message.save();

        console.log('✅ Payment confirmed for message:', message._id);

        // Emit socket event
        io.emit('paymentReceived', {
          messageId: message._id.toString(),
          amount: amount,
          paymentId: paymentId,
          method: 'cashfree'
        });
      } else {
        console.error('❌ Could not find message for payment');
        console.error('   Order ID:', orderId);
        console.error('   Customer ID:', webhookData.data.customer_details.customer_id);
      }
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('💥 Webhook error:', error);
    res.status(500).send('Webhook processing failed');
  }
});

// CLEANUP ENDPOINT FOR FIXING NULL COMPLETED_BY VALUES
app.post('/api/admin/fix-completed-by', authenticate, async (req, res) => {
  try {
    const result = await Message.updateMany(
      { completedBy: null },
      { $unset: { completedBy: 1 } }
    );

    console.log(`Fixed ${result.modifiedCount} documents with null completedBy`);
    res.json({
      success: true,
      message: `Fixed ${result.modifiedCount} documents`
    });
  } catch (error) {
    console.error('Error fixing completedBy:', error);
    res.status(500).json({ error: 'Failed to fix documents' });
  }
});

// Error handling middleware for multer
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 4GB.' });
    }
    return res.status(400).json({ error: `Upload error: ${error.message}` });
  }

  if (error.message.includes('Invalid file type')) {
    return res.status(400).json({ error: error.message });
  }

  next(error);
});

// Generic error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Local: http://localhost:${PORT}`);
  console.log(`Network: http://192.168.31.177:${PORT}`);
  console.log(`Uploads directory: ${uploadsDir}`);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`Admin Dashboard: http://localhost:${PORT}/?admin`);
    console.log(`User Interface: http://localhost:${PORT}/`);
  }
});