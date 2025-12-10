// ============================================
// SCRIPT PARA CRIAR USUÁRIO ADMINISTRADOR
// ============================================
// Uso: node scripts/create-admin.js

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const readline = require('readline');
require('dotenv').config();

// Schema do usuário (mesmo do server.js)
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
        required: true
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

const User = mongoose.model('User', UserSchema);

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function question(query) {
    return new Promise(resolve => rl.question(query, resolve));
}

async function createAdmin() {
    try {
        // Conecta ao MongoDB
        console.log('Conectando ao MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/compremais', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('✓ Conectado ao MongoDB\n');

        // Solicita dados do usuário
        console.log('=== CRIAR USUÁRIO ADMINISTRADOR ===\n');
        
        const username = await question('Nome de usuário: ');
        
        if (username.length < 3) {
            console.error('✗ Nome de usuário deve ter pelo menos 3 caracteres');
            process.exit(1);
        }

        // Verifica se usuário já existe
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            console.error('✗ Usuário já existe!');
            process.exit(1);
        }

        let password = await question('Senha (mínimo 8 caracteres): ');
        
        if (password.length < 8) {
            console.error('✗ Senha deve ter pelo menos 8 caracteres');
            process.exit(1);
        }

        const passwordConfirm = await question('Confirme a senha: ');
        
        if (password !== passwordConfirm) {
            console.error('✗ As senhas não coincidem');
            process.exit(1);
        }

        const role = await question('Tipo de usuário (admin/viewer) [admin]: ') || 'admin';
        
        if (!['admin', 'viewer'].includes(role)) {
            console.error('✗ Tipo inválido. Use "admin" ou "viewer"');
            process.exit(1);
        }

        // Hash da senha
        console.log('\nCriando usuário...');
        const hashedPassword = await bcrypt.hash(password, 12);

        // Cria usuário
        const user = new User({
            username,
            password: hashedPassword,
            role
        });

        await user.save();

        console.log('\n✓ Usuário criado com sucesso!');
        console.log(`Username: ${username}`);
        console.log(`Role: ${role}`);
        console.log('\nGuarde estas credenciais em local seguro!\n');

    } catch (error) {
        console.error('✗ Erro ao criar usuário:', error.message);
    } finally {
        rl.close();
        mongoose.connection.close();
        process.exit(0);
    }
}

createAdmin();
