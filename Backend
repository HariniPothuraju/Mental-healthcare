const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Environment variables
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/serenemind';
const JWT_SECRET = process.env.JWT_SECRET || 'serenemind_secret_key_2024';


// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('🌸 Connected to MongoDB successfully!'))
.catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Mood Entry Schema
const moodEntrySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    emoji: { type: String, required: true },
    value: { type: Number, required: true, min: 1, max: 10 },
    note: { type: String, default: '' },
    date: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// Chat Message Schema
const chatMessageSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['user', 'bot'], required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Goal Schema
const goalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    completed: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    completedAt: { type: Date }
});

const noteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const appointmentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    doctor: { type: String, required: true },
    doctorId: { type: String },
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    date: { type: String, required: true },
    time: { type: String, required: true },
    reason: { type: String },
    status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        productId: { type: Number, required: true },
        name: { type: String, required: true },
        price: { type: Number, required: true },
        icon: { type: String },
        quantity: { type: Number, default: 1 }
    }],
    total: { type: Number, required: true },
    customer: {
        name: { type: String, required: true },
        email: { type: String, required: true },
        phone: { type: String, required: true },
        address: { type: String, required: true },
        city: { type: String, required: true },
        zipCode: { type: String, required: true }
    },
    paymentMethod: { type: String, enum: ['online', 'offline'], required: true },
    status: { type: String, enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const MoodEntry = mongoose.model('MoodEntry', moodEntrySchema);
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);
const Goal = mongoose.model('Goal', goalSchema);
const Note = mongoose.model('Note', noteSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const Order = mongoose.model('Order', orderSchema);

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) {
            return res.status(401).json({ error: 'Invalid token.' });
        }
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
};


app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email.' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });
        
        await user.save();
        
        // Generate token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.status(201).json({
            message: 'User created successfully! 🌸',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        
        // Generate token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        
        res.json({
            message: 'Login successful! 💕',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    res.json({ user: req.user });
});

// Create mood entry
app.post('/api/moods', authenticateToken, async (req, res) => {
    try {
        const { emoji, value, note } = req.body;
        
        const moodEntry = new MoodEntry({
            userId: req.user._id,
            emoji,
            value,
            note: note || ''
        });
        
        await moodEntry.save();
        
        res.status(201).json({
            message: 'Mood logged successfully! 🌸',
            mood: moodEntry
        });
    } catch (error) {
        console.error('Mood creation error:', error);
        res.status(500).json({ error: 'Failed to log mood.' });
    }
});

// Get all mood entries for user
app.get('/api/moods', authenticateToken, async (req, res) => {
    try {
        const moods = await MoodEntry.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
        
        // Calculate statistics
        const totalMoods = moods.length;
        const averageMood = totalMoods > 0 
            ? Math.round(moods.reduce((sum, m) => sum + m.value, 0) / totalMoods)
            : 0;
        const bestMood = totalMoods > 0 
            ? Math.max(...moods.map(m => m.value))
            : 0;
        
        res.json({
            moods,
            stats: {
                total: totalMoods,
                average: averageMood,
                best: bestMood,
                streak: totalMoods // Simplified streak calculation
            }
        });
    } catch (error) {
        console.error('Fetch moods error:', error);
        res.status(500).json({ error: 'Failed to fetch moods.' });
    }
});

app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { type, text } = req.body;
        
        const message = new ChatMessage({
            userId: req.user._id,
            type,
            text
        });
        
        await message.save();
        
        res.status(201).json({
            message: 'Chat saved successfully! 💕',
            chat: message
        });
    } catch (error) {
        console.error('Chat save error:', error);
        res.status(500).json({ error: 'Failed to save chat.' });
    }
});

// Get chat history
app.get('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        const chats = await ChatMessage.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
        
        res.json({ chats: chats.reverse() });
    } catch (error) {
        console.error('Fetch chats error:', error);
        res.status(500).json({ error: 'Failed to fetch chats.' });
    }
});

// Clear chat history
app.delete('/api/chat', authenticateToken, async (req, res) => {
    try {
        await ChatMessage.deleteMany({ userId: req.user._id });
        res.json({ message: 'Chat history cleared! 🌿' });
    } catch (error) {
        console.error('Clear chats error:', error);
        res.status(500).json({ error: 'Failed to clear chats.' });
    }
});
// Create goal
app.post('/api/goals', authenticateToken, async (req, res) => {
    try {
        const { text } = req.body;
        
        const goal = new Goal({
            userId: req.user._id,
            text
        });
        
        await goal.save();
        
        res.status(201).json({
            message: 'Goal created! 🎯',
            goal
        });
    } catch (error) {
        console.error('Goal creation error:', error);
        res.status(500).json({ error: 'Failed to create goal.' });
    }
});

// Get all goals
app.get('/api/goals', authenticateToken, async (req, res) => {
    try {
        const goals = await Goal.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
        
        res.json({ goals });
    } catch (error) {
        console.error('Fetch goals error:', error);
        res.status(500).json({ error: 'Failed to fetch goals.' });
    }
});

// Update goal
app.put('/api/goals/:id', authenticateToken, async (req, res) => {
    try {
        const { completed } = req.body;
        
        const goal = await Goal.findOne({ _id: req.params.id, userId: req.user._id });
        if (!goal) {
            return res.status(404).json({ error: 'Goal not found.' });
        }
        
        goal.completed = completed;
        if (completed) {
            goal.completedAt = new Date();
        } else {
            goal.completedAt = null;
        }
        
        await goal.save();
        
        res.json({
            message: 'Goal updated! ✨',
            goal
        });
    } catch (error) {
        console.error('Goal update error:', error);
        res.status(500).json({ error: 'Failed to update goal.' });
    }
});

// Delete goal
app.delete('/api/goals/:id', authenticateToken, async (req, res) => {
    try {
        const goal = await Goal.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
        if (!goal) {
            return res.status(404).json({ error: 'Goal not found.' });
        }
        
        res.json({ message: 'Goal deleted! 🌸' });
    } catch (error) {
        console.error('Goal deletion error:', error);
        res.status(500).json({ error: 'Failed to delete goal.' });
    }
});
// Create note
app.post('/api/notes', authenticateToken, async (req, res) => {
    try {
        const { text } = req.body;
        
        const note = new Note({
            userId: req.user._id,
            text
        });
        
        await note.save();
        
        res.status(201).json({
            message: 'Note saved! 📝',
            note
        });
    } catch (error) {
        console.error('Note creation error:', error);
        res.status(500).json({ error: 'Failed to save note.' });
    }
});

// Get all notes
app.get('/api/notes', authenticateToken, async (req, res) => {
    try {
        const notes = await Note.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
        
        res.json({ notes });
    } catch (error) {
        console.error('Fetch notes error:', error);
        res.status(500).json({ error: 'Failed to fetch notes.' });
    }
});

// Create appointment
app.post('/api/appointments', authenticateToken, async (req, res) => {
    try {
        const { doctor, name, email, phone, date, time, reason } = req.body;
        
        const appointment = new Appointment({
            userId: req.user._id,
            doctor,
            name,
            email,
            phone,
            date,
            time,
            reason: reason || ''
        });
        
        await appointment.save();
        
        res.status(201).json({
            message: 'Appointment booked! 💕',
            appointment
        });
    } catch (error) {
        console.error('Appointment creation error:', error);
        res.status(500).json({ error: 'Failed to book appointment.' });
    }
});

// Get all appointments
app.get('/api/appointments', authenticateToken, async (req, res) => {
    try {
        const appointments = await Appointment.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
        
        res.json({ appointments });
    } catch (error) {
        console.error('Fetch appointments error:', error);
        res.status(500).json({ error: 'Failed to fetch appointments.' });
    }
});

// Update appointment status
app.put('/api/appointments/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        
        const appointment = await Appointment.findOne({ _id: req.params.id, userId: req.user._id });
        if (!appointment) {
            return res.status(404).json({ error: 'Appointment not found.' });
        }
        
        appointment.status = status;
        await appointment.save();
        
        res.json({
            message: 'Appointment updated! ✨',
            appointment
        });
    } catch (error) {
        console.error('Appointment update error:', error);
        res.status(500).json({ error: 'Failed to update appointment.' });
    }
});

// Create order
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { items, total, customer, paymentMethod } = req.body;
        
        const order = new Order({
            userId: req.user._id,
            items,
            total,
            customer,
            paymentMethod
        });
        
        await order.save();
        
        res.status(201).json({
            message: 'Order placed with love! 💕',
            order
        });
    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({ error: 'Failed to place order.' });
    }
});

// Get all orders
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.user._id })
            .sort({ createdAt: -1 });
        
        res.json({ orders });
    } catch (error) {
        console.error('Fetch orders error:', error);
        res.status(500).json({ error: 'Failed to fetch orders.' });
    }
});

// Get dashboard statistics
app.get('/api/dashboard', authenticateToken, async (req, res) => {
    try {
        const [moods, chats, appointments, goals, notes] = await Promise.all([
            MoodEntry.countDocuments({ userId: req.user._id }),
            ChatMessage.countDocuments({ userId: req.user._id }),
            Appointment.countDocuments({ userId: req.user._id }),
            Goal.countDocuments({ userId: req.user._id }),
            Note.countDocuments({ userId: req.user._id })
        ]);
        
        // Get recent mood entries for chart
        const recentMoods = await MoodEntry.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(7);
        
        res.json({
            stats: {
                totalMoods: moods,
                totalChats: chats,
                totalAppointments: appointments,
                totalGoals: goals,
                totalNotes: notes
            },
            recentMoods: recentMoods.reverse()
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data.' });
    }
});

app.post('/api/ai/respond', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        const lowerMsg = message.toLowerCase();
        
        let response = "";
        
        if (lowerMsg.includes('sad') || lowerMsg.includes('depressed')) {
            response = "💙 Your feelings are valid. I'm here with you. Would you like to talk about what's making you feel this way? Remember, it's okay to not be okay sometimes.";
        } else if (lowerMsg.includes('anxiety') || lowerMsg.includes('anxious') || lowerMsg.includes('worry')) {
            response = "🌿 Let's breathe together for a moment. Inhale deeply... 1, 2, 3... exhale slowly... 1, 2, 3... You're safe. Anxiety is just a feeling, and feelings pass. Would you like some grounding exercises?";
        } else if (lowerMsg.includes('happy') || lowerMsg.includes('joy') || lowerMsg.includes('great')) {
            response = "✨ What beautiful energy! I'm so glad you're feeling joy! It's wonderful to celebrate these moments. What's bringing you happiness today?";
        } else if (lowerMsg.includes('stressed') || lowerMsg.includes('overwhelm')) {
            response = "🌸 It sounds like you're carrying a lot. Remember to be gentle with yourself. Would you like to try a quick mindfulness exercise? Take three deep breaths with me...";
        } else if (lowerMsg.includes('lonely') || lowerMsg.includes('alone')) {
            response = "💕 You are not alone. I'm here with you, and there are people who care about you. Sometimes reaching out to someone you trust can help. Would you like to talk more about how you're feeling?";
        } else if (lowerMsg.includes('thank')) {
            response = "💖 You're so welcome! It's my joy to be here with you. Remember, you're doing amazing work taking care of yourself.";
        } else {
            response = "🌸 Thank you for sharing your beautiful heart with me. I'm listening with so much love. Tell me more about what's on your mind today. Remember, every feeling you have is valid and important.";
        }
        
        // Save the bot response to chat history
        const botMessage = new ChatMessage({
            userId: req.user._id,
            type: 'bot',
            text: response
        });
        await botMessage.save();
        
        res.json({ response });
    } catch (error) {
        console.error('AI response error:', error);
        res.status(500).json({ error: 'Failed to get AI response.' });
    }
});


app.get('/api/doctors', authenticateToken, async (req, res) => {
    const doctors = [
        { 
            id: 1,
            name: "Dr. Revanth Kumar", 
            specialty: "Senior Psychiatrist", 
            experience: "15+ years", 
            rating: 4.9, 
            reviews: 128, 
            icon: "👨‍⚕️",
            bio: "Specializes in anxiety, depression, and mood disorders. Compassionate care with evidence-based approaches.",
            availability: ["Monday", "Wednesday", "Friday"]
        },
        { 
            id: 2,
            name: "Dr. Sai Lakshmi", 
            specialty: "Clinical Psychologist", 
            experience: "12+ years", 
            rating: 4.8, 
            reviews: 95, 
            icon: "👩‍⚕️",
            bio: "Expert in cognitive behavioral therapy, trauma healing, and stress management.",
            availability: ["Tuesday", "Thursday", "Saturday"]
        },
        { 
            id: 3,
            name: "Dr. Meera Nair", 
            specialty: "Mental Health Counselor", 
            experience: "8+ years", 
            rating: 4.9, 
            reviews: 112, 
            icon: "👩‍⚕️",
            bio: "Holistic approach focusing on mindfulness, life transitions, and emotional wellness.",
            availability: ["Monday", "Tuesday", "Thursday", "Friday"]
        }
    ];
    
    res.json({ doctors });
});



app.get('/api/products', authenticateToken, async (req, res) => {
    const products = [
        { id: 1, name: "Mindfulness Journal", price: 24.99, description: "Daily prompts for gentle reflection", icon: "📔", category: "journals", inStock: true },
        { id: 2, name: "Calm Essential Oil Set", price: 39.99, description: "Lavender, chamomile, bergamot blend", icon: "🌿", category: "aromatherapy", inStock: true },
        { id: 3, name: "Stress Relief Tea", price: 19.99, description: "Organic calming herbal blend", icon: "🍵", category: "tea", inStock: true },
        { id: 4, name: "Meditation Cushion", price: 49.99, description: "Ergonomic support for peaceful practice", icon: "🧘", category: "accessories", inStock: true },
        { id: 5, name: "Gratitude Cards", price: 14.99, description: "52 daily gratitude prompts", icon: "💝", category: "cards", inStock: true },
        { id: 6, name: "Wellness Planner", price: 29.99, description: "Track your beautiful journey", icon: "📅", category: "planners", inStock: true }
    ];
    
    res.json({ products });
});


app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        message: '🌸 SereneMind API is running beautifully!',
        timestamp: new Date().toISOString()
    });
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again later.' });
});

app.listen(PORT, () => {
    console.log(`🌸 SereneMind Backend Server is running on port ${PORT}`);
    console.log(`📝 Health check: http://localhost:${PORT}/api/health`);
});
