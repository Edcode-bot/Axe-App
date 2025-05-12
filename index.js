const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const connectDB = require('./db');

const User = require('./models/User');
const Payment = require('./models/Payment');
const Property = require('./models/Property');
const Message = require('./models/Message');
const GroupMessage = require('./models/GroupMessage');

const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

connectDB();

if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + '-' + file.originalname);
  }
});
const upload = multer({ storage });

app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: 'axe_secret_key', resave: false, saveUninitialized: true }));

io.on('connection', socket => {
  socket.on('joinRoom', ({ userId, otherUserId }) => {
    const room = [userId, otherUserId].sort().join('_');
    socket.join(room);
  });

  socket.on('sendMessage', async ({ senderId, recipientId, content }) => {
    const room = [senderId, recipientId].sort().join('_');
    const message = new Message({ sender: senderId, recipient: recipientId, content });
    await message.save();
    io.to(room).emit('newMessage', { senderId, content, timestamp: new Date() });
  });

  socket.on('joinGroup', ({ propertyId }) => socket.join(propertyId));

  socket.on('sendGroupMessage', async ({ senderId, propertyId, content }) => {
    const msg = new GroupMessage({ sender: senderId, property: propertyId, content });
    await msg.save();
    io.to(propertyId).emit('newGroupMessage', {
      senderId, content, isFile: content.includes('/uploads/'), timestamp: new Date()
    });
  });
});

// ROUTES
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/tenant-dashboard', (req, res) => {
  if (!req.session.userId || req.session.role !== 'tenant') return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public/tenant-dashboard.html'));
});
app.get('/landlord-dashboard', (req, res) => {
  if (!req.session.userId || req.session.role !== 'landlord') return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public/landlord-dashboard.html'));
});

app.post('/register', async (req, res) => {
  const { name, phone, password, role } = req.body;
  try {
    const existingUser = await User.findOne({ phone });
    if (existingUser) return res.send('User already exists.');
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, phone, password: hashedPassword, role });
    await newUser.save();
    res.send('Registration successful. You can now log in.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Registration failed.');
  }
});

app.post('/login', async (req, res) => {
  const { phone, password } = req.body;
  try {
    const user = await User.findOne({ phone });
    if (!user) return res.send('User not found.');
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send('Incorrect password.');
    req.session.userId = user._id;
    req.session.role = user.role;
    if (user.role === 'tenant') return res.redirect('/tenant-dashboard');
    if (user.role === 'landlord') return res.redirect('/landlord-dashboard');
    res.send('Invalid role.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Login failed.');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// ---- Payments ----

app.post('/make-payment', async (req, res) => {
  const { amount } = req.body;
  if (!req.session.userId || req.session.role !== 'tenant') return res.status(401).send('Unauthorized');
  try {
    const payment = new Payment({ user: req.session.userId, amount });
    await payment.save();
    res.redirect('/tenant-dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Payment failed.');
  }
});

app.get('/my-payments', async (req, res) => {
  if (!req.session.userId || req.session.role !== 'tenant') return res.status(401).json([]);
  try {
    const payments = await Payment.find({ user: req.session.userId }).sort({ date: -1 });
    res.json(payments);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.get('/payments', async (req, res) => {
  try {
    const payments = await Payment.find().populate('user');
    let html = `<h2>All Tenant Payments</h2><ul>`;
    payments.forEach(p => {
      html += `<li>${p.user.name || 'Unnamed'} (${p.user.phone}) paid $${p.amount} on ${new Date(p.date).toLocaleDateString()}</li>`;
    });
    html += `</ul><a href="/landlord-dashboard">Back</a>`;
    res.send(html);
  } catch (err) {
    res.status(500).send('Error loading payments.');
  }
});

// ---- Properties ----

app.post('/add-property', async (req, res) => {
  const { name, address } = req.body;
  if (!req.session.userId || req.session.role !== 'landlord') return res.status(403).send('Unauthorized');
  try {
    const property = new Property({ name, address, landlord: req.session.userId });
    await property.save();
    res.redirect('/landlord-dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Add property failed.');
  }
});

app.get('/my-properties', async (req, res) => {
  if (!req.session.userId || req.session.role !== 'landlord') return res.status(403).json([]);
  try {
    const properties = await Property.find({ landlord: req.session.userId }).populate('tenants', 'name phone');
    res.json(properties);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post('/assign-tenant', async (req, res) => {
  const { propertyId, tenantPhone } = req.body;
  if (!req.session.userId || req.session.role !== 'landlord') return res.status(403).send('Unauthorized');
  try {
    const tenant = await User.findOne({ phone: tenantPhone });
    if (!tenant || tenant.role !== 'tenant') return res.send('Tenant not found.');
    const property = await Property.findOne({ _id: propertyId, landlord: req.session.userId });
    if (!property) return res.status(404).send('Property not found.');
    if (!property.tenants.includes(tenant._id)) {
      property.tenants.push(tenant._id);
      await property.save();
    }
    res.redirect('/landlord-dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Tenant assignment failed.');
  }
});

// ---- Group Chat ----

app.get('/tenant-group-chat', async (req, res) => {
  if (!req.session.userId || req.session.role !== 'tenant') return res.redirect('/login');
  const property = await Property.findOne({ tenants: req.session.userId });
  if (!property) return res.send('You are not assigned to a property.');
  res.sendFile(path.join(__dirname, 'public/tenant-group-chat.html'));
});

app.get('/group-messages', async (req, res) => {
  const { property } = req.query;
  if (!property) return res.status(400).json([]);
  try {
    const messages = await GroupMessage.find({ property }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json([]);
  }
});

app.post('/upload-file', upload.single('file'), async (req, res) => {
  const { senderId, propertyId } = req.body;
  if (!req.file) return res.status(400).send('No file uploaded');
  const fileUrl = `/uploads/${req.file.filename}`;
  const msg = new GroupMessage({ sender: senderId, property: propertyId, content: fileUrl });
  await msg.save();
  io.to(propertyId).emit('newGroupMessage', {
    senderId, content: fileUrl, isFile: true, timestamp: new Date()
  });
  res.send({ status: 'success', fileUrl });
});

// ---- One-on-One Chat ----

app.get('/chat', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const user = await User.findById(req.session.userId);
  let peer = null;
  if (user.role === 'tenant') {
    const property = await Property.findOne({ tenants: user._id }).populate('landlord');
    if (property) peer = property.landlord;
  } else if (user.role === 'landlord') {
    const tenantId = req.query.with;
    if (tenantId) peer = await User.findById(tenantId);
  }

  const peerName = peer ? peer.name || peer.phone : "No one";

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Chat with ${peerName}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <script src="/socket.io/socket.io.js"></script>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      <style>
        body { background-color: #f0f2f5; }
        #chatContainer {
          max-width: 600px;
          margin: auto;
          background: white;
          border-radius: 12px;
          box-shadow: 0 0 10px rgba(0,0,0,0.1);
          padding: 20px;
        }
        #messages {
          max-height: 400px;
          overflow-y: auto;
          padding-bottom: 1rem;
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .bubble {
          padding: 10px 14px;
          border-radius: 20px;
          max-width: 75%;
          word-wrap: break-word;
        }
        .me {
          align-self: flex-end;
          background-color: #d1e7dd;
        }
        .them {
          align-self: flex-start;
          background-color: #f1f0f0;
        }
      </style>
    </head>
    <body>
      <div class="container py-4">
        <div id="chatContainer">
          <h5 class="mb-3">Chat with ${peerName}</h5>
          <div id="messages"></div>
          <form id="chatForm" class="mt-3">
            <input type="text" id="messageInput" class="form-control mb-2" placeholder="Type a message..." autocomplete="off">
            <button class="btn btn-primary w-100" type="submit">Send</button>
          </form>
        </div>
      </div>
      <script>
        const socket = io();
        const senderId = "${user._id}";
        const recipientId = "${peer ? peer._id : ''}";
        const messages = document.getElementById('messages');
        if (!recipientId) {
          document.getElementById('chatForm').remove();
          messages.innerHTML = "<p>No chat recipient found.</p>";
        } else {
          socket.emit('joinRoom', { userId: senderId, otherUserId: recipientId });
          fetch('/messages?with=' + recipientId)
            .then(res => res.json())
            .then(data => {
              data.forEach(m => {
                const div = document.createElement('div');
                div.className = 'bubble ' + (m.sender === senderId ? 'me' : 'them');
                div.innerHTML = m.content;
                messages.appendChild(div);
              });
              messages.scrollTop = messages.scrollHeight;
            });

          const form = document.getElementById('chatForm');
          const input = document.getElementById('messageInput');
          form.addEventListener('submit', e => {
            e.preventDefault();
            const content = input.value;
            if (!content) return;
            socket.emit('sendMessage', { senderId, recipientId, content });
            input.value = '';
          });

          socket.on('newMessage', data => {
            const div = document.createElement('div');
            div.className = 'bubble ' + (data.senderId === senderId ? 'me' : 'them');
            div.innerHTML = data.content;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
          });
        }
      </script>
    </body>
    </html>
  `);
});

app.get('/messages', async (req, res) => {
  if (!req.session.userId) return res.status(401).json([]);
  const userId = req.session.userId;
  const withUser = req.query.with;
  try {
    const messages = await Message.find({
      $or: [
        { sender: userId, recipient: withUser },
        { sender: withUser, recipient: userId }
      ]
    }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json([]);
  }
});

// ---- Start Server ----
const PORT = 3000;
http.listen(PORT, () => {
  console.log(`🚀 Axe App running at http://localhost:${PORT}`);
});