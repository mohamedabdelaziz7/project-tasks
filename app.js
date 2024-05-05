const express =require("express")
const mongoose = require('mongoose');
const userRoutes = require('./routes/userRoutes');
const { validateRegister, validateLogin } = require('./middleware/auth');
const app = express();

// 
app.use(express.json());
require('dotenv').config();

// 
mongoose.connect(process.env.DB_CONNECTION_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  //
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// 
app.use('/api/users', userRoutes);

// 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});