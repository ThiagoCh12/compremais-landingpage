// ============================================
// BACKEND API - Supermercado Compre Mais
// ============================================
// Node.js + Express + PostgreSQL/MongoDB
// 
// Instalação:
// npm init -y
// npm install express cors helmet express-rate-limit express-validator jsonwebtoken bcryptjs dotenv mongoose joi

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const Joi = require('joi');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1); // ← ADICIONE ESTA LINHA

// ============================================
// CONFIGURAÇÕES DE SEGURANÇA
// ============================================

// Helmet - Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configurado de forma restritiva
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400 // 24 horas
};
app.use(cors(corsOptions));

// Body parser com limite de tamanho
app.use(express.json({ limit: '10kb' }));

// Remove header X-Powered-By
app.disable('x-powered-by');

// ============================================
// RATE LIMITING
// ============================================

// Rate limiter para analytics (mais permissivo)
const analyticsLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // 100 requisições por IP
    message: 'Muitas requisições deste IP, tente novamente mais tarde.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limiter para autenticação (mais restritivo)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // 5 tentativas de login
    skipSuccessfulRequests: true,
    message: 'Muitas tentativas de login, aguarde 15 minutos.'
});

// Rate limiter para dashboard (proteção adicional)
const dashboardLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 30,
    message: 'Limite de requisições excedido.'
});

// ============================================
// SCHEMAS DE VALIDAÇÃO
// ============================================

// Schema para evento de analytics
const analyticsEventSchema = Joi.object({
    type: Joi.string().valid('page_view', 'whatsapp_click', 'page_exit', 'scroll_depth').required(),
    timestamp: Joi.date().iso().required(),
    page: Joi.object({
        url: Joi.string().uri().max(500).required(),
        title: Joi.string().max(200).required(),
        referrer: Joi.string().uri().max(500).allow('', null)
    }).required(),
    data: Joi.object().optional()
});

// Schema para login
const loginSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(8).required()
});

// ============================================
// CONEXÃO COM BANCO DE DADOS (MongoDB)
// ============================================

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/compremais')

.then(() => console.log('✓ Conectado ao MongoDB'))
.catch(err => {
    console.error('✗ Erro ao conectar MongoDB:', err);
    process.exit(1);
});

// ============================================
// MODELOS DO BANCO DE DADOS
// ============================================

// Schema de Analytics Event
const AnalyticsEventSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['page_view', 'whatsapp_click', 'page_exit', 'scroll_depth'],
        required: true,
        index: true
    },
    timestamp: {
        type: Date,
        required: true,
        index: true
    },
    location: {
        ip: {
            type: String,
            required: true
        },
        city: String,
        region: String,
        country: String,
        latitude: Number,
        longitude: Number
    },
    device: {
        type: {
            type: String,
            enum: ['Mobile', 'Desktop', 'Tablet']
        },
        userAgent: String,
        screenWidth: Number,
        screenHeight: Number,
        language: String
    },
    page: {
        url: String,
        title: String,
        referrer: String
    },
    data: mongoose.Schema.Types.Mixed,
    sessionId: {
        type: String,
        index: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 7776000 // Auto-delete após 90 dias
    }
});

// Índices compostos para queries otimizadas
AnalyticsEventSchema.index({ timestamp: -1, type: 1 });
AnalyticsEventSchema.index({ 'location.ip': 1, timestamp: -1 });

const AnalyticsEvent = mongoose.model('AnalyticsEvent', AnalyticsEventSchema);

// Schema de Usuário Admin
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
        select: false // Nunca retorna a senha em queries
    },
    role: {
        type: String,
        enum: ['admin', 'viewer'],
        default: 'viewer'
    },
    lastLogin: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Hash da senha antes de salvar
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

const User = mongoose.model('User', UserSchema);

// ============================================
// MIDDLEWARES DE SEGURANÇA
// ============================================

// Sanitização de entrada
function sanitizeInput(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const sanitized = {};
    for (let key in obj) {
        if (typeof obj[key] === 'string') {
            // Remove caracteres perigosos
            sanitized[key] = obj[key]
                .replace(/[<>\"']/g, '')
                .substring(0, 500); // Limita tamanho
        } else if (typeof obj[key] === 'object') {
            sanitized[key] = sanitizeInput(obj[key]);
        } else {
            sanitized[key] = obj[key];
        }
    }
    return sanitized;
}

// Middleware de autenticação JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Token de autenticação necessário' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido ou expirado' });
        }
        req.user = user;
        next();
    });
}

// Middleware para verificar role de admin
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Permissão de administrador necessária.' });
    }
    next();
}

// Middleware de validação com Joi
function validateRequest(schema) {
    return (req, res, next) => {
        const { error } = schema.validate(req.body, { abortEarly: false });
        if (error) {
            const errors = error.details.map(detail => detail.message);
            return res.status(400).json({ error: 'Validação falhou', details: errors });
        }
        next();
    };
}

// Extração segura de IP
function getClientIP(req) {
    // Verifica se há proxy reverso confiável
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded && process.env.TRUST_PROXY === 'true') {
        return forwarded.split(',')[0].trim();
    }
    return req.ip || req.connection.remoteAddress;
}

// ============================================
// ROTAS PÚBLICAS (Analytics)
// ============================================

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Receber eventos de analytics (sem autenticação, mas com rate limit)
app.post('/api/analytics/event',
    analyticsLimiter,
    validateRequest(analyticsEventSchema),
    async (req, res) => {
        try {
            // Sanitiza entrada
            const sanitizedData = sanitizeInput(req.body);
            
            // Extrai IP do cliente de forma segura
            const clientIP = getClientIP(req);
            
            // Obtém geolocalização do IP (em produção, use cache ou serviço local)
            let locationData = {
                ip: clientIP,
                city: 'Desconhecido',
                region: 'Desconhecido',
                country: 'Desconhecido'
            };
            
            // Em produção, implemente aqui a lógica de geolocalização
            // Exemplo: usar serviço local ou cache
            
            // Obtém informações do dispositivo
            const userAgent = req.headers['user-agent'] || '';
            let deviceType = 'Desktop';
            if (/Mobile|Android|iPhone/i.test(userAgent)) {
                deviceType = 'Mobile';
            } else if (/iPad|Tablet/i.test(userAgent)) {
                deviceType = 'Tablet';
            }
            
            const deviceInfo = {
                type: deviceType,
                userAgent: userAgent.substring(0, 200), // Limita tamanho
                language: req.headers['accept-language']?.split(',')[0] || 'unknown'
            };
            
            // Cria evento no banco
            const event = new AnalyticsEvent({
                type: sanitizedData.type,
                timestamp: sanitizedData.timestamp,
                location: locationData,
                device: deviceInfo,
                page: sanitizedData.page,
                data: sanitizedData.data,
                sessionId: req.headers['x-session-id'] || null
            });
            
            await event.save();
            
            // Resposta mínima (não expõe dados sensíveis)
            res.status(201).json({ 
                success: true,
                id: event._id 
            });
            
        } catch (error) {
            console.error('Erro ao salvar evento:', error);
            // Não expõe detalhes do erro para o cliente
            res.status(500).json({ error: 'Erro ao processar evento' });
        }
    }
);

// ============================================
// ROTAS DE AUTENTICAÇÃO
// ============================================

// Login
app.post('/api/auth/login',
    authLimiter,
    validateRequest(loginSchema),
    async (req, res) => {
        try {
            const { username, password } = req.body;
            
            // Busca usuário com senha
            const user = await User.findOne({ username }).select('+password');
            
            if (!user) {
                // Tempo de resposta consistente para evitar timing attacks
                await bcrypt.compare(password, '$2a$12$dummyhashtopreventtimingattack');
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }
            
            // Verifica senha
            const validPassword = await bcrypt.compare(password, user.password);
            
            if (!validPassword) {
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }
            
            // Atualiza último login
            user.lastLogin = new Date();
            await user.save();
            
            // Gera token JWT
            const token = jwt.sign(
                { 
                    id: user._id, 
                    username: user.username, 
                    role: user.role 
                },
                process.env.JWT_SECRET,
                { expiresIn: '8h' }
            );
            
            // Retorna token
            res.json({
                success: true,
                token,
                user: {
                    username: user.username,
                    role: user.role
                }
            });
            
        } catch (error) {
            console.error('Erro no login:', error);
            res.status(500).json({ error: 'Erro no servidor' });
        }
    }
);

// Verificar token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ 
        valid: true, 
        user: {
            username: req.user.username,
            role: req.user.role
        }
    });
});

// ============================================
// ROTAS PROTEGIDAS (Dashboard)
// ============================================

// Obter estatísticas agregadas
app.get('/api/dashboard/stats',
    authenticateToken,
    dashboardLimiter,
    async (req, res) => {
        try {
            const { startDate, endDate, eventType } = req.query;
            
            // Validação de datas
            const query = {};
            
            if (startDate) {
                query.timestamp = { $gte: new Date(startDate) };
            }
            if (endDate) {
                query.timestamp = { ...query.timestamp, $lte: new Date(endDate) };
            }
            if (eventType && eventType !== 'all') {
                query.type = eventType;
            }
            
            // Queries otimizadas com agregação
            const [
                totalEvents,
                uniqueVisitors,
                whatsappClicks,
                deviceStats,
                topCities,
                timeSeriesData
            ] = await Promise.all([
                // Total de eventos
                AnalyticsEvent.countDocuments(query),
                
                // Visitantes únicos (por IP)
                AnalyticsEvent.distinct('location.ip', query).then(ips => ips.length),
                
                // Cliques no WhatsApp
                AnalyticsEvent.countDocuments({ ...query, type: 'whatsapp_click' }),
                
                // Estatísticas de dispositivos
                AnalyticsEvent.aggregate([
                    { $match: query },
                    { $group: { _id: '$device.type', count: { $sum: 1 } } }
                ]),
                
                // Top 5 cidades
                AnalyticsEvent.aggregate([
                    { $match: query },
                    { $group: { _id: '$location.city', count: { $sum: 1 } } },
                    { $sort: { count: -1 } },
                    { $limit: 5 }
                ]),
                
                // Dados da série temporal (últimos 30 dias)
                AnalyticsEvent.aggregate([
                    { $match: query },
                    {
                        $group: {
                            _id: {
                                $dateToString: { format: '%Y-%m-%d', date: '$timestamp' }
                            },
                            count: { $sum: 1 }
                        }
                    },
                    { $sort: { _id: 1 } },
                    { $limit: 30 }
                ])
            ]);
            
            // Taxa de conversão
            const conversionRate = uniqueVisitors > 0 
                ? ((whatsappClicks / uniqueVisitors) * 100).toFixed(2)
                : 0;
            
            res.json({
                success: true,
                data: {
                    totalEvents,
                    uniqueVisitors,
                    whatsappClicks,
                    conversionRate,
                    devices: deviceStats,
                    topCities: topCities.map(city => ({
                        city: city._id,
                        count: city.count
                    })),
                    timeSeries: timeSeriesData.map(item => ({
                        date: item._id,
                        count: item.count
                    }))
                }
            });
            
        } catch (error) {
            console.error('Erro ao obter estatísticas:', error);
            res.status(500).json({ error: 'Erro ao processar estatísticas' });
        }
    }
);

// Obter eventos recentes
app.get('/api/dashboard/recent',
    authenticateToken,
    dashboardLimiter,
    async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const skip = parseInt(req.query.skip) || 0;
            
            const events = await AnalyticsEvent
                .find()
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(limit)
                .select('-__v') // Remove campo de versão
                .lean(); // Retorna objeto JS simples (mais rápido)
            
            res.json({
                success: true,
                data: events,
                pagination: {
                    limit,
                    skip,
                    hasMore: events.length === limit
                }
            });
            
        } catch (error) {
            console.error('Erro ao obter eventos recentes:', error);
            res.status(500).json({ error: 'Erro ao processar eventos' });
        }
    }
);

// Exportar dados (apenas admin)
app.get('/api/dashboard/export',
    authenticateToken,
    requireAdmin,
    async (req, res) => {
        try {
            const { startDate, endDate, format = 'json' } = req.query;
            
            const query = {};
            if (startDate) query.timestamp = { $gte: new Date(startDate) };
            if (endDate) query.timestamp = { ...query.timestamp, $lte: new Date(endDate) };
            
            const events = await AnalyticsEvent
                .find(query)
                .sort({ timestamp: -1 })
                .limit(10000) // Limita exportação
                .lean();
            
            if (format === 'csv') {
                // Converte para CSV
                const csv = convertToCSV(events);
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', 'attachment; filename=analytics-export.csv');
                res.send(csv);
            } else {
                res.json({
                    success: true,
                    data: events,
                    count: events.length
                });
            }
            
        } catch (error) {
            console.error('Erro ao exportar dados:', error);
            res.status(500).json({ error: 'Erro ao exportar dados' });
        }
    }
);

// ============================================
// FUNÇÕES AUXILIARES
// ============================================

function convertToCSV(events) {
    const headers = ['Timestamp', 'Type', 'City', 'Region', 'Country', 'Device', 'URL'];
    const rows = events.map(e => [
        new Date(e.timestamp).toISOString(),
        e.type,
        e.location.city,
        e.location.region,
        e.location.country,
        e.device.type,
        e.page.url
    ]);
    
    return [headers, ...rows]
        .map(row => row.map(cell => `"${cell}"`).join(','))
        .join('\n');
}

// ============================================
// TRATAMENTO DE ERROS GLOBAL
// ============================================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint não encontrado' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err);
    
    // Não expõe detalhes do erro em produção
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    res.status(err.status || 500).json({
        error: isDevelopment ? err.message : 'Erro interno do servidor',
        ...(isDevelopment && { stack: err.stack })
    });
});

// ============================================
// INICIALIZAÇÃO DO SERVIDOR
// ============================================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`✓ Servidor rodando na porta ${PORT}`);
    console.log(`✓ Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log(`✓ CORS permitido para: ${process.env.ALLOWED_ORIGINS || 'localhost'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM recebido. Encerrando servidor...');
    mongoose.connection.close(() => {
        console.log('Conexão com MongoDB encerrada');
        process.exit(0);
    });
});

module.exports = app; // Para testes
