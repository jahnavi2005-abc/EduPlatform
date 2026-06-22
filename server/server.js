// server/server.js

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';

import hpp from 'hpp';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import cluster from 'cluster';
import os from 'os';

// Import routes
import authRoutes from './routes/authRoutes.js';
import courseRoutes from './routes/courseRoutes.js';
import uploadRoutes from './routes/uploadRoutes.js';
import studentRoutes from './routes/studentRoutes.js';
import notificationRoutes from './routes/notificationRoutes.js';
import instructorRoutes from './routes/instructorRoutes.js';
import contactRoutes from './routes/contactRoutes.js';
import adminRoutes from './routes/adminRoutes.js';

// Import middleware
import { setSecurityHeaders, errorHandler } from './utils/security.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
let server; // Declare server globally for graceful shutdown
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const isProduction = NODE_ENV === 'production';

console.log(`🚀 Starting server in ${NODE_ENV} mode...`);

// ========== Database Connection ==========

const mongoUrl = process.env.MONGO_URI;

const connectToDatabase = async () => {
  try {
    const mongooseOptions = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 5,
      retryWrites: true,
      w: 'majority'
    };

    await mongoose.connect(mongoUrl, mongooseOptions);

    console.log("✅ MongoDB connected successfully");

    // Connection event listeners
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️ MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('🔌 MongoDB reconnected');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('🛑 MongoDB connection closed through app termination');
      process.exit(0);
    });

  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  }
};

// ========== Cloudinary Configuration ==========

try {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
  console.log("☁️ Cloudinary configured successfully");
} catch (err) {
  console.error("❌ Cloudinary configuration error:", err);
}

// ========== Create logs directory ==========

const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// ========== Security Middleware ==========

// 1. Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: isProduction ? {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", process.env.FRONTEND_URL],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  } : false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// 2. Custom security headers
app.use(setSecurityHeaders);

// 3. CORS configuration
// 3. CORS configuration
// 3. CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // Check if origin is localhost or 127.0.0.1
    if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
      return callback(null, true);
    }

    // Check specific allowed domains
    const allowedDomains = [process.env.FRONTEND_URL];
    if (allowedDomains.indexOf(origin) !== -1) {
      return callback(null, true);
    }

    // For development, we might want to be permissive if above fails but we are in dev mode
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }

    console.warn(`⚠️ CORS blocked origin: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'Access-Control-Allow-Headers', 'X-API-Key'],
  exposedHeaders: ['Content-Length', 'X-Powered-By', 'X-Response-Time'],
  optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}));

// 4. Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 100 : 5000, // limit each IP to 100 requests per windowMs in production
  message: {
    status: 429,
    message: 'Too many requests from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health';
  },
  // Fix for ERR_ERL_KEY_GEN_IPV6
  validate: { ip: false, trustProxy: false }
});

app.use(limiter);

// 5. Body parsing
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// 6. Data sanitization
app.use((req, res, next) => {
  if (req.body) mongoSanitize.sanitize(req.body);
  if (req.params) mongoSanitize.sanitize(req.params);
  next();
});
app.use(hpp()); // Against HTTP parameter pollution

// 7. Compression
app.use(compression());

// ========== Logging ==========

// Morgan logging configuration
const logFormat = isProduction ? 'combined' : 'dev';
const accessLogStream = fs.createWriteStream(
  path.join(logsDir, 'access.log'),
  { flags: 'a' }
);

app.use(morgan(logFormat, {
  stream: accessLogStream,
  skip: (req) => req.path === '/health' // Skip health checks in logs
}));

app.use(morgan(logFormat));

// Custom request logging middleware
app.use((req, res, next) => {
  const start = Date.now();

  // Log request details
  console.log(`${req.method} ${req.path} - IP: ${req.ip}`);

  // Capture response finish
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} ${res.statusCode} - ${duration}ms`);

    // Log slow requests
    if (duration > 1000) {
      console.warn(`⚠️ Slow request detected: ${req.method} ${req.path} took ${duration}ms`);
    }
  });

  next();
});

// ========== Static Files ==========

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ========== Health Check ==========

app.get('/health', (req, res) => {
  const healthcheck = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: Date.now(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
    environment: NODE_ENV
  };

  try {
    res.status(200).json(healthcheck);
  } catch (error) {
    healthcheck.message = error;
    res.status(503).json(healthcheck);
  }
});

// ========== API Documentation ==========

app.get('/api/docs', (req, res) => {
  res.json({
    name: 'EduPlatform API',
    version: '1.0.0',
    description: 'Learning Management System API',
    endpoints: {
      auth: '/api/auth',
      courses: '/api/courses',
      students: '/api/students',
      notifications: '/api/notifications',
      uploads: '/api/upload'
    },
    status: 'active',
    documentation: 'https://docs.eduplatform.com'
  });
});

// ========== API Routes ==========

console.log("🧩 Registering API routes...");

// Auth routes
app.use("/api/auth", authRoutes);

// Course routes
app.use("/api", courseRoutes);

// Upload routes
app.use("/api/upload", uploadRoutes);

// Student routes
app.use("/api/students", studentRoutes);

// Notification routes
app.use("/api/notifications", notificationRoutes);

// Instructor routes
app.use("/api/instructors", instructorRoutes);

// Contact routes
app.use("/api/contact", contactRoutes);

// Admin routes
app.use("/api/admin", adminRoutes);

// ========== 404 Handler ==========

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
    error: {
      code: 'ROUTE_NOT_FOUND',
      suggestions: [
        'Check the API documentation at /api/docs',
        'Verify the endpoint URL',
        'Ensure you have proper authentication'
      ]
    }
  });
});

// ========== Global Error Handler ==========

app.use(errorHandler);

// ========== Graceful Shutdown ==========

const gracefulShutdown = (signal) => {
  console.log(`\n⚠️ Received ${signal}. Starting graceful shutdown...`);

  // Close server
  server.close(() => {
    console.log('🛑 HTTP server closed');

    // Close database connection
    mongoose.connection.close().then(() => {
      console.log('🛑 MongoDB connection closed');
      console.log('👋 Graceful shutdown complete');
      process.exit(0);
    });
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('⚠️ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

// ========== Start Server ==========

const startServer = async () => {
  try {
    // Connect to database
    await connectToDatabase();

    // Start server
    server = app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🌐 Environment: ${NODE_ENV}`);
      console.log(`📚 API Documentation: http://localhost:${PORT}/api/docs`);
      console.log(`❤️  Health Check: http://localhost:${PORT}/health`);

      if (!isProduction) {
        console.log('\n📋 Development Info:');
        console.log(`   Frontend URL: ${process.env.FRONTEND_URL}`);
        console.log(`   MongoDB: ${mongoUrl.split('@')[1] || mongoUrl}`);
      }
    });

    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        process.exit(1);
      } else {
        console.error('❌ Server error:', error);
        process.exit(1);
      }
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
      // Close server & exit process
      server.close(() => process.exit(1));
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('❌ Uncaught Exception:', error);
      // Close server & exit process
      server.close(() => process.exit(1));
    });

    // Listen for shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    return server;

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// ========== Cluster Mode (Production Only) ==========

if (isProduction && cluster.isPrimary) {
  const numCPUs = 1; // Limited to 1 for free tier
  console.log(`🖥️  Master ${process.pid} is running`);
  console.log(`🔢 Forking ${numCPUs} workers...`);

  // Fork workers
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.log(`⚠️ Worker ${worker.process.pid} died`);
    console.log('🔄 Starting a new worker...');
    cluster.fork();
  });

} else {
  // Worker process
  startServer().then(server => {
    console.log(`👷 Worker ${process.pid} started`);
  });
}

// Export app for testing
export default app;