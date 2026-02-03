<?php
session_start();

// --- DATABASE CONFIGURATION ---
// Change 'sqlite' to 'mysql' if you want to use a MySQL server.
$db_type = 'sqlite'; 

// MySQL Credentials (only used if $db_type is 'mysql')
$db_host = 'localhost';
$db_name = 'trakr_db';
$db_user = 'root';
$db_pass = '';

try {
    if ($db_type === 'sqlite') {
        // SQLite: Database is a file in the current directory
        $pdo = new PDO('sqlite:' . __DIR__ . '/database.sqlite');
    } else {
        // MySQL Connection
        $dsn = "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4";
        $pdo = new PDO($dsn, $db_user, $db_pass);
    }
    
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // --- TABLE CREATION (Cross-compatible) ---
    $pk = ($db_type === 'sqlite') ? "INTEGER PRIMARY KEY AUTOINCREMENT" : "INT AUTO_INCREMENT PRIMARY KEY";
    $strCol = ($db_type === 'sqlite') ? "TEXT" : "VARCHAR(191)";
    
    // Ensure tables exist
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id $pk, 
        email $strCol UNIQUE, 
        password TEXT, 
        is_premium INTEGER DEFAULT 0, 
        unlocked_features TEXT, 
        role TEXT DEFAULT 'user',
        two_factor_secret TEXT,
        data_json TEXT
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS blocked_ips (ip $strCol PRIMARY KEY, reason TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS settings (name $strCol UNIQUE, value TEXT)");

} catch (PDOException $e) {
    die("Database Connection Error: " . $e->getMessage()); 
}

$ip = $_SERVER['REMOTE_ADDR'];
$whitelisted_ip = '42.110.162.59';

// --- 1. IP Check (Intrusion Detection) ---
if ($ip !== $whitelisted_ip) {
    $stmt = $pdo->prepare("SELECT * FROM blocked_ips WHERE ip = ?");
    $stmt->execute([$ip]);
    if ($stmt->fetch()) {
        http_response_code(403);
        die("<h1>403 Forbidden</h1><p>Your IP has been blocked.</p>");
    }
}

// --- 2. AJAX API Handler (Secure) ---
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    // Auth Check for API
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
        echo json_encode(['status' => 'error', 'error' => 'Unauthorized']);
        exit;
    }

    $action = $_GET['api'];
    $input = json_decode(file_get_contents('php://input'), true);

    if ($action === 'get_data') {
        // Fetch System Config
        $stmt = $pdo->query("SELECT value FROM settings WHERE name = 'system_config'");
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $config = $row ? json_decode($row['value'], true) : [];
        
        // Default values
        $defaultConfig = [
            'openai_api_key' => '',
            'gemini_api_key' => '',
            'google_client_id' => '',
            'facebook_client_id' => '',
            'whatsapp_api_key' => '',
            'whatsapp_phone_number_id' => '',
            'vapid_public_key' => '',
            'vapid_private_key' => ''
        ];
        
        $config = array_merge($defaultConfig, $config);

        // Fetch Users
        $users = $pdo->query("SELECT id, email, role, is_premium FROM users ORDER BY id DESC LIMIT 100")->fetchAll(PDO::FETCH_ASSOC);

        // Fetch Blocked IPs
        $blockedIps = $pdo->query("SELECT * FROM blocked_ips ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);

        // Stats
        $stats = [
            'total_users' => count($users),
            'blocked_ips' => count($blockedIps),
            'premium_users' => count(array_filter($users, fn($u) => $u['is_premium'] == 1))
        ];

        echo json_encode([
            'status' => 'success',
            'data' => [
                'config' => $config,
                'users' => $users,
                'blockedIps' => $blockedIps,
                'stats' => $stats
            ]
        ]);
        exit;
    }

    if ($action === 'promote_user' && isset($input['id'])) {
        $pdo->prepare("UPDATE users SET is_premium = 1 WHERE id = ?")->execute([$input['id']]);
        echo json_encode(['status' => 'success']);
        exit;
    }

    if ($action === 'delete_user' && isset($input['id'])) {
        if ($input['id'] != $_SESSION['user_id']) {
            $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$input['id']]);
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error', 'error' => 'Cannot delete self']);
        }
        exit;
    }

    if ($action === 'unblock_ip' && isset($input['ip'])) {
        $pdo->prepare("DELETE FROM blocked_ips WHERE ip = ?")->execute([$input['ip']]);
        echo json_encode(['status' => 'success']);
        exit;
    }

    if ($action === 'save_config') {
        $pdo->prepare("INSERT OR REPLACE INTO settings (name, value) VALUES ('system_config', ?)")->execute([json_encode($input)]);
        echo json_encode(['status' => 'success']);
        exit;
    }
    
    exit;
}

// --- 3. Login Logic ---
$loginError = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'admin_login') {
    $email = $_POST['email'] ?? '';
    $pass = $_POST['password'] ?? '';

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($pass, $user['password'])) {
        if ($user['role'] === 'admin') {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = 'admin';
            header("Location: admin.php");
            exit;
        } else {
            $loginError = "Access Restricted";
            if ($ip !== $whitelisted_ip) {
                $pdo->prepare("INSERT OR IGNORE INTO blocked_ips (ip, reason) VALUES (?, 'Unauthorized Role Access')")->execute([$ip]);
            }
        }
    } else {
        $loginError = "Invalid credentials";
    }
}

// --- 4. Render Interface ---
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    // Login Screen
    ?>
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TraKr Admin | Login</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body class="bg-[#020617] text-white h-screen flex items-center justify-center p-4">
        <div class="w-full max-w-sm bg-[#0f172a] p-8 rounded-2xl border border-white/10 shadow-2xl">
            <h1 class="text-2xl font-bold text-center mb-6">Admin Panel</h1>
            <?php if($loginError): ?>
                <div class="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-bold rounded-lg text-center"><?php echo $loginError; ?></div>
            <?php endif; ?>
            <form method="POST" class="space-y-4">
                <input type="hidden" name="action" value="admin_login">
                <input type="email" name="email" required placeholder="Email" class="w-full bg-black/20 border border-white/10 rounded-lg px-4 py-3 text-white">
                <input type="password" name="password" required placeholder="Password" class="w-full bg-black/20 border border-white/10 rounded-lg px-4 py-3 text-white">
                <button type="submit" class="w-full py-3 bg-indigo-600 hover:bg-indigo-500 rounded-lg font-bold">Login</button>
            </form>
            <div class="mt-4 text-center"><a href="index.html" class="text-xs text-slate-500 hover:text-white">← Back</a></div>
        </div>
    </body>
    </html>
    <?php
    exit;
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraKr | Admin Console</title>
    <link rel="icon" href="assets/trakr-logo.png" type="image/png">
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Inter', 'sans-serif'] },
                    colors: {
                        dark: '#020617',
                        surface: '#0f172a',
                        glass: 'rgba(255, 255, 255, 0.05)',
                    }
                }
            }
        }
    </script>
    
    <!-- FontAwesome & Alpine -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.13.3/dist/cdn.min.js"></script>
    
    <style>
        body { font-family: 'Inter', sans-serif; }
        .glass-card { background: rgba(30, 41, 59, 0.5); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
        .glass-input { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); color: white; }
        .glass-input:focus { border-color: #3b82f6; outline: none; }
        [x-cloak] { display: none !important; }
        .loading-skeleton { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; background: rgba(255,255,255,0.05); }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
    </style>
</head>
<body class="bg-dark text-slate-200 min-h-screen" x-data="adminApp()" x-init="init()" x-cloak>

    <!-- Sidebar -->
    <div class="fixed top-0 left-0 h-full w-64 bg-surface border-r border-white/5 p-6 hidden md:flex flex-col z-20">
        <div class="flex items-center gap-3 mb-10">
            <div class="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white font-bold text-xs">TK</div>
            <h1 class="text-xl font-bold tracking-tight text-white">Admin<span class="text-indigo-500">Panel</span></h1>
        </div>
        
        <nav class="space-y-2 flex-1">
            <template x-for="item in menuItems">
                <button @click="currentTab = item.id" 
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all"
                        :class="currentTab === item.id ? 'bg-indigo-500/10 text-indigo-400' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'">
                    <i :class="item.icon"></i>
                    <span x-text="item.label"></span>
                </button>
            </template>
        </nav>
        
        <button @click="logout" class="flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold text-red-500 hover:bg-red-500/10 transition-colors">
            <i class="fa-solid fa-right-from-bracket"></i> Logout
        </button>
    </div>

    <!-- Mobile Header -->
    <div class="md:hidden p-4 bg-surface border-b border-white/5 flex justify-between items-center sticky top-0 z-30">
        <h1 class="font-bold text-white">TraKr Admin</h1>
        <button @click="showMobileMenu = !showMobileMenu" class="text-slate-400"><i class="fa-solid fa-bars"></i></button>
    </div>

    <!-- Main Content -->
    <main class="md:ml-64 p-4 md:p-8 max-w-7xl mx-auto pb-20">
        
        <!-- Dashboard Tab -->
        <div x-show="currentTab === 'dashboard'" class="space-y-8">
            <header>
                <h2 class="text-3xl font-bold text-white mb-2">System Overview</h2>
                <p class="text-slate-500 text-sm">Real-time platform statistics.</p>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Stat Cards with Lazy Loading -->
                <template x-for="(stat, label) in { 'Total Users': stats.total_users, 'Premium': stats.premium_users, 'Blocked IPs': stats.blocked_ips }">
                    <div class="glass-card p-6 rounded-2xl relative overflow-hidden">
                        <div x-show="loading" class="absolute inset-0 loading-skeleton z-10"></div>
                        <div class="flex justify-between items-start mb-4">
                            <div class="p-3 rounded-xl bg-blue-500/10 text-blue-500"><i class="fa-solid fa-chart-simple"></i></div>
                            <span class="text-xs font-bold text-slate-500 uppercase" x-text="label"></span>
                        </div>
                        <h3 class="text-3xl font-bold text-white" x-text="stat"></h3>
                    </div>
                </template>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Quick User List -->
                <div class="glass-card p-6 rounded-2xl min-h-[300px] relative">
                    <div x-show="loading" class="absolute inset-0 z-10 p-6 space-y-4">
                         <div class="h-8 w-1/3 loading-skeleton rounded"></div>
                         <div class="space-y-2">
                             <div class="h-12 w-full loading-skeleton rounded-xl"></div>
                             <div class="h-12 w-full loading-skeleton rounded-xl"></div>
                             <div class="h-12 w-full loading-skeleton rounded-xl"></div>
                         </div>
                    </div>
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="font-bold text-white">Recent Users</h3>
                        <button @click="currentTab = 'users'" class="text-xs font-bold text-indigo-400">View All</button>
                    </div>
                    <div class="space-y-4">
                        <template x-for="u in users.slice(0, 5)" :key="u.id">
                            <div class="flex items-center justify-between p-3 rounded-xl hover:bg-white/5 transition-colors">
                                <div class="flex items-center gap-3">
                                    <div class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-xs font-bold" x-text="u.email.substring(0,1).toUpperCase()"></div>
                                    <div>
                                        <p class="text-sm font-bold text-white" x-text="u.email"></p>
                                        <p class="text-[10px] text-slate-500" x-text="u.role"></p>
                                    </div>
                                </div>
                                <span x-show="u.is_premium == 1" class="px-2 py-1 rounded-md bg-amber-500/10 text-amber-500 text-[10px] font-bold">PRO</span>
                            </div>
                        </template>
                    </div>
                </div>

                <!-- Server Info -->
                <div class="glass-card p-6 rounded-2xl">
                    <h3 class="font-bold text-white mb-6">Server Status</h3>
                    <div class="space-y-4">
                        <div class="flex justify-between text-sm border-b border-white/5 pb-2">
                            <span class="text-slate-400">PHP Version</span>
                            <span class="text-white font-mono"><?php echo phpversion(); ?></span>
                        </div>
                        <div class="flex justify-between text-sm border-b border-white/5 pb-2">
                            <span class="text-slate-400">Server IP</span>
                            <span class="text-white font-mono"><?php echo $_SERVER['SERVER_ADDR'] ?? '127.0.0.1'; ?></span>
                        </div>
                        <div class="flex justify-between text-sm border-b border-white/5 pb-2">
                            <span class="text-slate-400">Database</span>
                            <span class="text-white font-mono">
                                <?php echo ($db_type === 'sqlite') ? 'SQLite3' : 'MySQL'; ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Settings Tab -->
        <div x-show="currentTab === 'settings'" class="space-y-6">
            <header class="mb-8">
                <h2 class="text-3xl font-bold text-white mb-2">System Configuration</h2>
            </header>

            <div class="glass-card p-8 rounded-2xl max-w-2xl relative">
                <div x-show="loading" class="absolute inset-0 loading-skeleton z-10 rounded-2xl"></div>
                
                <h3 class="text-lg font-bold text-indigo-400 mb-6 uppercase tracking-widest text-xs border-b border-white/5 pb-2">Artificial Intelligence</h3>
                
                <div class="space-y-5">
                    <div>
                        <label class="block text-xs font-bold text-slate-400 uppercase mb-2">OpenAI API Key (Legacy)</label>
                        <div class="relative">
                            <i class="fa-solid fa-key absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"></i>
                            <input type="password" x-model="config.openai_api_key" placeholder="sk-..." class="glass-input w-full rounded-xl pl-10 pr-4 py-3 text-sm">
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs font-bold text-slate-400 uppercase mb-2">Gemini API Key (Google AI)</label>
                        <div class="relative">
                            <i class="fa-brands fa-google absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"></i>
                            <input type="password" x-model="config.gemini_api_key" placeholder="AIza..." class="glass-input w-full rounded-xl pl-10 pr-4 py-3 text-sm">
                        </div>
                    </div>

                    <h3 class="text-lg font-bold text-indigo-400 mt-8 mb-6 uppercase tracking-widest text-xs border-b border-white/5 pb-2">OAuth Providers</h3>
                    
                    <div>
                        <label class="block text-xs font-bold text-slate-400 uppercase mb-2">Google Client ID</label>
                        <input type="text" x-model="config.google_client_id" placeholder="apps.googleusercontent.com" class="glass-input w-full rounded-xl px-4 py-3 text-sm">
                    </div>
                    
                    <div>
                        <label class="block text-xs font-bold text-slate-400 uppercase mb-2">Facebook App ID</label>
                        <input type="text" x-model="config.facebook_client_id" placeholder="App ID" class="glass-input w-full rounded-xl px-4 py-3 text-sm">
                    </div>

                    <h3 class="text-lg font-bold text-indigo-400 mt-8 mb-6 uppercase tracking-widest text-xs border-b border-white/5 pb-2">Communication Integration</h3>

                    <div class="space-y-5">
                        <!-- WhatsApp -->
                        <div>
                            <h4 class="font-bold text-white mb-4 flex items-center gap-2 text-sm"><i class="fa-brands fa-whatsapp text-green-500"></i> WhatsApp Business API</h4>
                            <div class="space-y-3">
                                <div>
                                    <label class="block text-xs font-bold text-slate-400 uppercase mb-2">Access Token</label>
                                    <input type="password" x-model="config.whatsapp_api_key" placeholder="EAAG..." class="glass-input w-full rounded-xl px-4 py-3 text-sm">
                                </div>
                                <div>
                                    <label class="block text-xs font-bold text-slate-400 uppercase mb-2">Phone Number ID</label>
                                    <input type="text" x-model="config.whatsapp_phone_number_id" placeholder="1059..." class="glass-input w-full rounded-xl px-4 py-3 text-sm">
                                </div>
                            </div>
                        </div>

                        <!-- Push Notifications -->
                        <div>
                            <h4 class="font-bold text-white mb-4 flex items-center gap-2 text-sm"><i class="fa-solid fa-bell text-yellow-500"></i> Push Notifications (Web Push)</h4>
                            <div class="space-y-3">
                                <div>
                                    <label class="block text-xs font-bold text-slate-400 uppercase mb-2">VAPID Public Key</label>
                                    <input type="text" x-model="config.vapid_public_key" placeholder="BM..." class="glass-input w-full rounded-xl px-4 py-3 text-sm">
                                </div>
                                <div>
                                    <label class="block text-xs font-bold text-slate-400 uppercase mb-2">VAPID Private Key</label>
                                    <input type="password" x-model="config.vapid_private_key" placeholder="Private Key" class="glass-input w-full rounded-xl px-4 py-3 text-sm">
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="pt-6">
                        <button @click="saveConfig" class="px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-indigo-600/20" :disabled="saving">
                            <span x-show="!saving"><i class="fa-solid fa-save mr-2"></i> Save Changes</span>
                            <span x-show="saving"><i class="fa-solid fa-circle-notch animate-spin mr-2"></i> Saving...</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Users Tab -->
        <div x-show="currentTab === 'users'" class="space-y-6">
             <header class="mb-8">
                <h2 class="text-3xl font-bold text-white mb-2">User Management</h2>
            </header>
            
            <div class="glass-card rounded-2xl overflow-hidden min-h-[200px] relative">
                <div x-show="loading" class="absolute inset-0 z-10 loading-skeleton"></div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead class="bg-white/5 text-xs uppercase text-slate-400">
                            <tr>
                                <th class="p-4">User</th>
                                <th class="p-4">Role</th>
                                <th class="p-4">Status</th>
                                <th class="p-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/5 text-sm">
                            <template x-for="u in users" :key="u.id">
                                <tr class="hover:bg-white/5 transition-colors">
                                    <td class="p-4">
                                        <div class="font-bold text-white" x-text="u.email"></div>
                                        <div class="text-[10px] text-slate-500" x-text="'ID: ' + u.id"></div>
                                    </td>
                                    <td class="p-4">
                                        <span class="px-2 py-1 rounded bg-slate-800 text-slate-300 text-xs font-bold uppercase" x-text="u.role"></span>
                                    </td>
                                    <td class="p-4">
                                        <template x-if="u.is_premium == 1">
                                            <span class="text-amber-500 font-bold text-xs"><i class="fa-solid fa-crown"></i> Premium</span>
                                        </template>
                                        <template x-if="u.is_premium != 1">
                                            <span class="text-slate-500 text-xs">Standard</span>
                                        </template>
                                    </td>
                                    <td class="p-4 text-right space-x-2">
                                        <button x-show="u.is_premium != 1" @click="promoteUser(u.id)" class="text-xs font-bold text-indigo-400 hover:text-indigo-300">Promote</button>
                                        <button @click="deleteUser(u.id)" class="text-xs font-bold text-red-500 hover:text-red-400">Delete</button>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Security Tab -->
        <div x-show="currentTab === 'security'" class="space-y-6">
            <header class="mb-8">
                <h2 class="text-3xl font-bold text-white mb-2">Security Audit</h2>
            </header>

            <div class="glass-card rounded-2xl overflow-hidden min-h-[200px] relative">
                 <div x-show="loading" class="absolute inset-0 z-10 loading-skeleton"></div>
                 <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead class="bg-white/5 text-xs uppercase text-slate-400">
                            <tr>
                                <th class="p-4">IP Address</th>
                                <th class="p-4">Reason</th>
                                <th class="p-4">Date Blocked</th>
                                <th class="p-4 text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/5 text-sm">
                            <template x-if="blockedIps.length === 0">
                                <tr><td colspan="4" class="p-8 text-center text-slate-500">No blocked IPs found. System is healthy.</td></tr>
                            </template>
                            <template x-for="b in blockedIps" :key="b.ip">
                                <tr class="hover:bg-white/5 transition-colors">
                                    <td class="p-4 font-mono text-red-400" x-text="b.ip"></td>
                                    <td class="p-4 text-slate-300" x-text="b.reason"></td>
                                    <td class="p-4 text-slate-500" x-text="b.created_at"></td>
                                    <td class="p-4 text-right">
                                        <button @click="unblockIp(b.ip)" class="px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 text-xs font-bold transition-colors">Unblock</button>
                                    </td>
                                </tr>
                            </template>
                        </tbody>
                    </table>
                 </div>
            </div>
        </div>

    </main>

<script>
    function adminApp() {
        return {
            currentTab: 'dashboard',
            showMobileMenu: false,
            loading: true,
            saving: false,
            config: {},
            users: [],
            blockedIps: [],
            stats: { total_users: 0, blocked_ips: 0, premium_users: 0 },
            
            menuItems: [
                { id: 'dashboard', label: 'Dashboard', icon: 'fa-solid fa-chart-line' },
                { id: 'settings', label: 'System Config', icon: 'fa-solid fa-sliders' },
                { id: 'users', label: 'Users', icon: 'fa-solid fa-users' },
                { id: 'security', label: 'Security', icon: 'fa-solid fa-shield-halved' }
            ],

            async init() {
                this.fetchData();
            },

            async fetchData() {
                this.loading = true;
                try {
                    const res = await fetch('admin.php?api=get_data').then(r => r.json());
                    if(res.status === 'success') {
                        this.config = res.data.config;
                        this.users = res.data.users;
                        this.blockedIps = res.data.blockedIps;
                        this.stats = res.data.stats;
                    }
                } catch(e) { console.error('Data Fetch Error', e); }
                this.loading = false;
            },

            async performAction(action, payload) {
                try {
                    const res = await fetch('admin.php?api=' + action, {
                        method: 'POST',
                        body: JSON.stringify(payload),
                        headers: { 'Content-Type': 'application/json' }
                    }).then(r => r.json());
                    
                    if(res.status === 'success') {
                        this.fetchData(); // Reload data
                    } else {
                        alert(res.error || 'Operation failed');
                    }
                } catch(e) { alert('Network Error'); }
            },

            saveConfig() {
                this.saving = true;
                fetch('admin.php?api=save_config', {
                    method: 'POST', body: JSON.stringify(this.config), headers: {'Content-Type': 'application/json'}
                }).then(() => { this.saving = false; alert('Saved'); });
            },

            promoteUser(id) { if(confirm('Promote to Premium?')) this.performAction('promote_user', {id}); },
            deleteUser(id) { if(confirm('Delete User?')) this.performAction('delete_user', {id}); },
            unblockIp(ip) { if(confirm('Unblock IP?')) this.performAction('unblock_ip', {ip}); },
            logout() { fetch('api.php?action=logout').then(() => window.location.href = 'index.html'); }
        }
    }
</script>
</body>
</html>