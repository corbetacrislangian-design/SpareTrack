const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();
const sequelize = require('./src/config/db');
const apiRoutes = require('./src/routes/apiRoutes');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', apiRoutes);

const PORT = process.env.PORT || 3000;

sequelize.authenticate()
  .then(() => {
    console.log('Connected to Cloud MySQL Database (SpareTrack 3NF Engine).');
    app.listen(PORT, () => {
      console.log(`SpareTrack Server running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Database connection failed. Check your .env cloud credentials:', err.message);
  });