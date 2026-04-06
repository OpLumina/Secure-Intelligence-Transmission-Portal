'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Install dependencies if node_modules is missing
const modulesPath = path.join(__dirname, 'src', 'node_modules');
if (!fs.existsSync(modulesPath)) {
    console.log('Installing dependencies...');
    execSync('npm install --omit=dev --ignore-scripts', {
        cwd: path.join(__dirname, 'src'),
        stdio: 'inherit'
    });
    console.log('Done.\n');
}

const bcrypt = require(path.join(modulesPath, 'bcryptjs'));

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Username (default: admin): ', (username) => {
    const user = username.trim() || 'admin';

    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(user)) {
        console.error('ERROR: Username must be 1-64 alphanumeric characters (_, - allowed).');
        rl.close();
        process.exit(1);
    }

    rl.question('Role [admin/user] (default: admin): ', (roleInput) => {
        const role = (roleInput.trim() || 'admin').toLowerCase();
        if (!['admin', 'user'].includes(role)) {
            console.error('ERROR: Role must be "admin" or "user".');
            rl.close();
            process.exit(1);
        }

        rl.question('Password: ', async (pw) => {
            // FIX BUG-1: Password minimum length check was commented out.
            // Restored — STIG SRG-APP-000171 requires strong one-way hash,
            // which is meaningless if a blank/trivial password is allowed.
            if (!pw || pw.length < 20) {
                console.error('ERROR: Password must be at least 20 characters (STIG SRG-APP-000171).');
                rl.close();
                process.exit(1);
            }

            // Reject passwords that are only whitespace
            if (pw.trim().length === 0) {
                console.error('ERROR: Password must not be only whitespace.');
                rl.close();
                process.exit(1);
            }

            try {
                // Cost factor 12 — STIG SRG-APP-000171 (strong one-way hash)
                const hash = await bcrypt.hash(pw, 12);

                let db = {};
                const dbPath = path.join(__dirname, 'db', 'users.db');
                if (fs.existsSync(dbPath)) {
                    db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
                }

                if (db[user]) {
                    console.warn(`WARNING: User '${user}' already exists and will be overwritten.`);
                }

                // Store {hash, role} — role is authoritative from DB, never inferred from username
                db[user] = { hash, role };
                // Write with mode 0o600 — readable only by owner (STIG V-222609)
                fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), { mode: 0o600 });
                console.log(`\nusers.db written. User '${user}' created with role '${role}'.`);
            } catch (e) {
                console.error('ERROR:', e.message);
                process.exit(1);
            }
            rl.close();
        });
    });
});