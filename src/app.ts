// File: src/app.ts (update to include Swagger UI)
import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import settings from './config/config';
import authRoutes from './routes/authRoutes';
import userRoutes from './routes/userRoutes';
import { errorHandler } from './middleware/errorMiddleware';
import { requestLogger } from './middleware/loggingMiddleware';
import { NotFoundError } from './utils/errorClasses';



const app: Application = express();

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API routes
const apiVersion = settings.api;
console.log(`API Version: ${apiVersion}`);

app.use(`/api/v1/auth`, authRoutes);
app.use(`/api/v1/users`, userRoutes);

// Handle undefined routes
app.all('*', (req: Request, res: Response, next: NextFunction) => {
  next(new NotFoundError(`Cannot find ${req.originalUrl} on this server`));
});

// Global error handler
app.use(errorHandler);

// Request logger
app.use(requestLogger);

export default app;