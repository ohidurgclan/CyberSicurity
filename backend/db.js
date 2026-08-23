import 'dotenv/config';
import { Pool } from 'pg';

const useSSL = process.env.PGSSL !== 'false';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { require: true } : false,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle Postgres client', err);
});

export default pool;
