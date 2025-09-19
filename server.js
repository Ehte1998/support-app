// Updated sections for your server.js file

// 1. Add validation for Razorpay credentials at startup
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error('CRITICAL: Razorpay credentials not found in environment variables');
  process.exit(1);
}

// 2. Initialize Razorpay with validation
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Test Razorpay connection
razorpay.orders.create({
  amount: 100, // ₹1 in paise
  currency: 'INR',
  receipt: 'test_receipt'
}).then(() => {
  console.log('✅ Razorpay connection successful');
}).catch((error) => {
  console.error('❌ Razorpay connection failed:', error.message);
});

// 3. Enhanced create payment order endpoint with better error handling
app.post('/api/create-payment-order', async (req, res) => {
  try {
    const { amount, messageId } = req.body;

    // Enhanced validation
    if (!amount || amount < 1) {
      return res.status(400).json({ 
        success: false, 
        error: 'Valid amount is required (minimum ₹1)' 
      });
    }

    if (amount > 100000) {
      return res.status(400).json({ 
        success: false, 
        error: 'Maximum amount is ₹1,00,000' 
      });
    }

    const amountInPaise = Math.round(amount * 100);
    
    // Create shorter receipt to stay under 40 characters
    const shortId = messageId ? messageId.substring(messageId.length - 8) : 'guest';
    const timestamp = Date.now().toString().slice(-8);
    const receipt = `rcpt_${shortId}_${timestamp}`;
    
    console.log(`Creating payment order: Amount=₹${amount}, Receipt=${receipt}`);
    
    const order = await razorpay.orders.create({
      amount: amountInPaise,
      currency: 'INR',
      receipt: receipt,
      payment_capture: 1,
      notes: {
        messageId: messageId || 'no_message',
        purpose: 'counseling_session'
      }
    });

    console.log(`✅ Payment order created: ${order.id} for ₹${amount}`);

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID // This will be the live key
    });
  } catch (error) {
    console.error('Payment order creation error:', error);
    
    // Send specific error messages for debugging
    if (error.error && error.error.code) {
      return res.status(400).json({ 
        success: false, 
        error: `Razorpay Error: ${error.error.description}`,
        code: error.error.code
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create payment order. Please try again.' 
    });
  }
});

// 4. Enhanced payment verification with better security
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { 
      razorpay_order_id, 
      razorpay_payment_id, 
      razorpay_signature, 
      messageId, 
      amount 
    } = req.body;

    // Validate required fields
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing payment verification data' 
      });
    }

    // Verify signature
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
                                    .update(body.toString())
                                    .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      console.error('Payment signature verification failed');
      return res.status(400).json({ 
        success: false, 
        error: 'Payment verification failed - invalid signature' 
      });
    }

    // Fetch payment details from Razorpay for additional verification
    try {
      const payment = await razorpay.payments.fetch(razorpay_payment_id);
      
      if (payment.status !== 'captured' && payment.status !== 'authorized') {
        return res.status(400).json({ 
          success: false, 
          error: 'Payment not successful' 
        });
      }

      console.log(`✅ Payment verified: ${razorpay_payment_id} - ₹${payment.amount / 100}`);
    } catch (fetchError) {
      console.error('Error fetching payment details:', fetchError);
      // Continue with verification if fetch fails, as signature was valid
    }

    // Update message with payment info
    if (messageId) {
      try {
        await Message.findByIdAndUpdate(messageId, {
          paymentStatus: 'paid',
          paymentId: razorpay_payment_id,
          amountPaid: amount / 100, // Convert from paise to rupees
          paidAt: new Date(),
          razorpayOrderId: razorpay_order_id
        });
        
        console.log(`✅ Message ${messageId} updated with payment info`);
      } catch (updateError) {
        console.error('Error updating message with payment:', updateError);
        // Payment was successful, so don't fail the verification
      }
    }

    // Emit payment received event to admin
    io.emit('paymentReceived', {
      messageId: messageId,
      amount: amount / 100,
      paymentId: razorpay_payment_id,
      orderId: razorpay_order_id
    });

    res.json({ 
      success: true, 
      message: 'Payment verified successfully',
      paymentId: razorpay_payment_id
    });

  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Payment verification failed - server error' 
    });
  }
});

// 5. Add webhook endpoint for Razorpay (recommended for production)
app.post('/api/razorpay-webhook', express.raw({type: 'application/json'}), (req, res) => {
  try {
    const webhookSignature = req.headers['x-razorpay-signature'];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET; // Add this to your .env
    
    if (webhookSecret) {
      const expectedSignature = crypto.createHmac('sha256', webhookSecret)
                                      .update(req.body)
                                      .digest('hex');
      
      if (expectedSignature !== webhookSignature) {
        return res.status(400).send('Invalid webhook signature');
      }
    }
    
    const event = JSON.parse(req.body);
    
    // Handle payment events
    if (event.event === 'payment.captured') {
      console.log('Payment captured via webhook:', event.payload.payment.entity.id);
      // You can add additional processing here
    }
    
    res.status(200).send('Webhook received');
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).send('Webhook error');
  }
});