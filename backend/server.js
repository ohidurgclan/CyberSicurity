import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth.js';

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api', authRoutes);

app.get('/', (req, res) => {
  res.json({ status: 'API is running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
