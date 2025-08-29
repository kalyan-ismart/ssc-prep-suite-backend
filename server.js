const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// Use the correct PORT binding for Render (uppercase PORT) and listen on 0.0.0.0
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

// Pull MongoDB connection string from Render environment variable
const uri = process.env.ATLAS_URI;

// Connect to MongoDB without deprecated options
mongoose.connect(uri)
  .then(() => console.log("MongoDB database connection established successfully"))
  .catch(err => console.error("MongoDB connection error:", err));

const connection = mongoose.connection;
connection.once('open', () => {
  console.log("MongoDB database connection established successfully");
});

// Routes
const modulesRouter = require('./routes/modules');
const progressRouter = require('./routes/progress');
const usersRouter = require('./routes/users');

app.use('/modules', modulesRouter);
app.use('/progress', progressRouter);
app.use('/users', usersRouter);

// Listen on the correct host and port (CRITICAL for Render)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port: ${PORT}`);
});
