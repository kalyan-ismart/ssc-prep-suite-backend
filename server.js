// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// MongoDB connection
const uri = "mongodb+srv://ssc-app-user:24pOkdxIDHy9bCyf@cluster0.c7ffaiw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
mongoose.connect(uri);
const connection = mongoose.connection;
connection.once('open', () => {
  console.log("MongoDB database connection established successfully");
})

// Routes
const modulesRouter = require('./routes/modules');
const progressRouter = require('./routes/progress');
const usersRouter = require('./routes/users');

app.use('/modules', modulesRouter);
app.use('/progress', progressRouter);
app.use('/users', usersRouter);

app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
});