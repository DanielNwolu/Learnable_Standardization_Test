import app from './app';
import { connectDB } from './config/db';
import config from "./config/config";

const PORT = config.server.port || 5000;

// Connect to database
connectDB().then(() => {
  // Start server
  app.listen(PORT, () => {
    console.log(`Server running in development mode on port ${PORT}`);
  });
});