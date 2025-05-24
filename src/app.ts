// File: src/app.ts (update to include Swagger UI)
import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import settings from './config/config';
import morgan from './utils/logger';
import authRoutes from './routes/authRoutes';
import userRoutes from './routes/userRoutes';
import decryptRoute from './routes/decryptDataRoute';
import { errorHandler } from './middleware/errorMiddleware';
import { requestLogger } from './middleware/loggingMiddleware';
import { NotFoundError } from './utils/errorClasses';
import homepageTemplate from './templates/homepage';
import { compileTemplateRaw } from './utils/templateEng';




const app: Application = express();

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: "50mb" }));



// MORGAN LOGGER MIDDLEWARE
app.use(morgan("[ :date ] :coloured-method :url :status :response-time ms"));

// Custom request logger middleware
// Route for home page
app.get('/', (req: Request, res: Response) => {
  res.send(compileTemplateRaw(homepageTemplate, {
    POSTMAN_DOC_LINK: settings.postmanDocLink,
    GITHUB_LINK: settings.githubRepoLink,
}
));
});


// API Version
const apiVersion = settings.api;
// API routes
app.use(`${apiVersion}/auth`, authRoutes);
app.use(`${apiVersion}/users`, userRoutes);
app.use(`${apiVersion}/decrypt`, decryptRoute);

// Handle undefined routes
app.all('*', (req: Request, res: Response, next: NextFunction) => {
  next(new NotFoundError(`Cannot find ${req.originalUrl} on this server`));
});

// Global error handler
app.use(errorHandler);

export default app;