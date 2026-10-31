import { Pool } from "pg";

// Never a real database: ROUTES points DATABASE_URL at a disposable sandbox database.
export const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4 });
