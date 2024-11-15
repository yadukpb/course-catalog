/**
* Copyright 2019 IBM
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*   you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, softwares
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
**/

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(compression());

const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
};


app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  trustProxy: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests, please try again later.'
    });
  }
});

app.use('/api/', limiter);

mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
  retryWrites: true,
  w: 'majority',
  tlsCAFile: process.env.CA_CERT_PATH,
  maxPoolSize: 50,
  wtimeoutMS: 2500
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  instructor: { type: String, required: true },
  semester: { type: String, required: true },
  courseCode: { type: String, required: true, unique: true },
  credits: { type: Number, required: true },
  prerequisites: String,
  createdBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  enrolledUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isEnrolled: { type: Boolean, default: false }
}, { timestamps: true });

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true }
});

const Course = mongoose.model('Course', courseSchema);
const User = mongoose.model('User', userSchema);

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

app.post('/api/courses', authenticateToken, async (req, res) => {
  try {
    const course = new Course({
      ...req.body,
      createdBy: req.user.id,
    });
    await course.save();
    res.status(201).json(course);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const { search, semester, credits } = req.query;
    
    const query = {
      createdBy: req.user.id
    };

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    if (semester && semester !== 'all') {
      query.semester = semester;
    }

    if (credits && credits !== 'all') {
      query.credits = parseInt(credits);
    }

    const courses = await Course.find(query)
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 })
      .lean();

    res.json(courses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/courses/user', authenticateToken, async (req, res) => {
  try {
    const courses = await Course.find({ createdBy: req.user.id });
    res.json(courses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findOne({
      _id: req.params.id,
      createdBy: req.user.id
    });
    if (!course) return res.status(404).json({ error: 'Course not found or unauthorized' });
    res.json(course);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findOneAndUpdate(
      { 
        _id: req.params.id,
        createdBy: req.user.id
      },
      req.body,
      { new: true }
    );
    if (!course) return res.status(404).json({ error: 'Course not found or unauthorized' });
    res.json(course);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findOneAndDelete({
      _id: req.params.id,
      createdBy: req.user.id
    });
    if (!course) return res.status(404).json({ error: 'Course not found or unauthorized' });
    res.json({ message: 'Course deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    
    let user = await User.findOne({ email: payload.email });
    if (!user) {
      user = await User.create({
        email: payload.email,
        name: payload.name,
        password: Math.random().toString(36).slice(-8)
      });
    }

    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ user, accessToken });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const existingUser = await User.findOne({ email });
    
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      name: name || email.split('@')[0]
    });
    
    await user.save();
    
    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.status(201).json({
      user: { id: user._id, email: user.email, name: user.name },
      accessToken
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({
      user: { id: user._id, email: user.email, name: user.name },
      accessToken
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/courses/details', authenticateToken, async (req, res) => {
  try {
    const courses = await Course.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'createdBy',
          foreignField: '_id',
          as: 'instructor'
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'enrolledUsers',
          foreignField: '_id',
          as: 'enrolledStudents'
        }
      },
      {
        $project: {
          title: 1,
          description: 1,
          instructor: { $arrayElemAt: ['$instructor.name', 0] },
          semester: 1,
          courseCode: 1,
          credits: 1,
          prerequisites: 1,
          enrolledCount: { $size: '$enrolledStudents' },
          enrolledStudents: {
            $map: {
              input: '$enrolledStudents',
              as: 'student',
              in: {
                id: '$$student._id',
                name: '$$student.name',
                email: '$$student.email'
              }
            }
          },
          createdAt: 1,
          updatedAt: 1
        }
      },
      {
        $sort: { createdAt: -1 }
      }
    ]);

    res.json(courses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use(express.static('public'));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});