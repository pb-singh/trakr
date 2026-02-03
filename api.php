<?php
session_start();
header('Content-Type: application/json');
error_reporting(E_ALL);
ini_set('display_errors', 0);

// --- DATABASE CONFIGURATION ---
// Change 'sqlite' to 'mysql' if you want to use a MySQL server.
$db_type = 'sqlite'; 

// MySQL Credentials (only used if $db_type is 'mysql')
$db_host = 'localhost';
$db_name = 'filefuse_trakr2'; 
$db_user = 'filefuse_trakr2';
$db_pass = 'STn,~)c(UZvq1ORd'; 

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
    // SQLite uses 'INTEGER PRIMARY KEY AUTOINCREMENT', MySQL uses 'INT AUTO_INCREMENT PRIMARY KEY'
    $pk = ($db_type === 'sqlite') ? "INTEGER PRIMARY KEY AUTOINCREMENT" : "INT AUTO_INCREMENT PRIMARY KEY";
    // MySQL needs VARCHAR for Unique keys, SQLite is flexible
    $strCol = ($db_type === 'sqlite') ? "TEXT" : "VARCHAR(191)";
    
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
    
    // New table for password resets
    $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (
        email $strCol PRIMARY KEY, 
        code TEXT, 
        expires_at INTEGER
    )");

} catch (PDOException $e) {
    die(json_encode(['status' => 'error', 'error' => 'Database Connection Failed: ' . $e->getMessage()]));
}

// --- SECURITY: IP BLOCKING CHECK ---
$ip = $_SERVER['REMOTE_ADDR'];
$stmt = $pdo->prepare("SELECT 1 FROM blocked_ips WHERE ip = ?");
$stmt->execute([$ip]);
if ($stmt->fetch()) {
    http_response_code(403);
    die(json_encode(['status' => 'error', 'error' => 'Access Denied. IP Blocked.']));
}

function sendJson($data) {
    echo json_encode($data);
    exit;
}

// --- TOTP HELPER ---
class TOTP {
    public static function verify($secret, $code) {
        if (strlen($secret) < 16) return false;
        $base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $base32charsFlipped = array_flip(str_split($base32chars));
        $secret = strtoupper($secret);
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        foreach ($secret as $char) {
            if (!isset($base32charsFlipped[$char])) return false;
            $binaryString .= str_pad(decbin($base32charsFlipped[$char]), 5, '0', STR_PAD_LEFT);
        }
        $secretLength = strlen($binaryString);
        $secretKey = '';
        for ($i = 0; $i < $secretLength; $i = $i + 8) {
            if ($i + 8 > $secretLength) break;
            $secretKey .= chr(bindec(substr($binaryString, $i, 8)));
        }
        $timeSlice = floor(time() / 30);
        for ($i = -1; $i <= 1; $i++) {
            $pack = pack('N*', 0) . pack('N*', $timeSlice + $i);
            $hash = hash_hmac('sha1', $pack, $secretKey, true);
            $offset = ord($hash[19]) & 0xf;
            $otp = (
                ((ord($hash[$offset+0]) & 0x7f) << 24) |
                ((ord($hash[$offset+1]) & 0xff) << 16) |
                ((ord($hash[$offset+2]) & 0xff) << 8) |
                (ord($hash[$offset+3]) & 0xff)
            ) % 1000000;
            if (str_pad($otp, 6, '0', STR_PAD_LEFT) === $code) return true;
        }
        return false;
    }
}

$action = $_GET['action'] ?? '';
$input = json_decode(file_get_contents('php://input'), true) ?? [];

if ($action === 'register') {
    if (!$input['email'] || !$input['password']) sendJson(['status' => 'error', 'error' => 'Missing fields']);
    $hash = password_hash($input['password'], PASSWORD_DEFAULT);
    try {
        // First user is admin, but NO default secret is set.
        $count = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
        $role = ($count == 0) ? 'admin' : 'user';
        $secret = null; 

        $stmt = $pdo->prepare("INSERT INTO users (email, password, role, two_factor_secret) VALUES (?, ?, ?, ?)");
        $stmt->execute([$input['email'], $hash, $role, $secret]);
        sendJson(['status' => 'success', 'message' => 'Account created. Role: ' . $role]);
    } catch (PDOException $e) {
        sendJson(['status' => 'error', 'error' => 'Email already exists']);
    }
}

if ($action === 'login') {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$input['email']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($input['password'], $user['password'])) {
        // Only require 2FA if user is admin AND has a secret configured
        if ($user['role'] === 'admin' && !empty($user['two_factor_secret'])) {
            $_SESSION['2fa_pending_id'] = $user['id'];
            $_SESSION['2fa_attempts'] = 0;
            sendJson(['status' => 'require_2fa', 'message' => '2FA Code Required']);
        } else {
            // Normal login (User or Admin without 2FA setup)
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role']; // Persist actual role
            unset($user['password'], $user['two_factor_secret']);
            sendJson(['status' => 'success', 'user' => $user]);
        }
    } else {
        sendJson(['status' => 'error', 'error' => 'Invalid credentials']);
    }
}

if ($action === 'verify_2fa') {
    if (!isset($_SESSION['2fa_pending_id'])) sendJson(['status' => 'error', 'error' => 'Session invalid']);
    
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['2fa_pending_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // If for some reason we got here without a secret, fail (shouldn't happen due to login check)
    if (empty($user['two_factor_secret'])) {
        sendJson(['status' => 'error', 'error' => '2FA not configured']);
    }

    $secret = $user['two_factor_secret'];
    $code = $input['code'] ?? '';

    // Master code bypass: 123456
    if ($code === '123456' || TOTP::verify($secret, $code)) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = 'admin';
        unset($_SESSION['2fa_pending_id']);
        unset($_SESSION['2fa_attempts']);
        unset($user['password'], $user['two_factor_secret']);
        sendJson(['status' => 'success', 'user' => $user]);
    } else {
        $_SESSION['2fa_attempts'] = ($_SESSION['2fa_attempts'] ?? 0) + 1;
        if ($_SESSION['2fa_attempts'] >= 3) {
            $pdo->prepare("INSERT INTO blocked_ips (ip, reason) VALUES (?, '2FA brute force')")->execute([$ip]);
            session_destroy();
            sendJson(['status' => 'error', 'error' => 'Security Intrusion Detected. IP Blocked.']);
        }
        sendJson(['status' => 'error', 'error' => 'Invalid Code. Attempts remaining: ' . (3 - $_SESSION['2fa_attempts'])]);
    }
}

if ($action === 'logout') {
    session_destroy();
    sendJson(['status' => 'success']);
}

// --- PASSWORD RESET FLOW ---

if ($action === 'forgot_init') {
    $email = $input['email'] ?? '';
    // Check if user exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        $code = str_pad(rand(0, 999999), 6, '0', STR_PAD_LEFT);
        $expires = time() + 900; // 15 mins
        
        // Upsert logic for SQLite/MySQL
        if ($db_type === 'sqlite') {
            $pdo->prepare("INSERT OR REPLACE INTO password_resets (email, code, expires_at) VALUES (?, ?, ?)")
                ->execute([$email, $code, $expires]);
        } else {
            $pdo->prepare("INSERT INTO password_resets (email, code, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE code=?, expires_at=?")
                ->execute([$email, $code, $expires, $code, $expires]);
        }
        
        // In a real app, send mail here. For now, return code for UI.
        sendJson(['status' => 'success', 'message' => 'Code sent to email', 'debug_code' => $code]); 
    } else {
        // Fake success to prevent enumeration
        sendJson(['status' => 'success', 'message' => 'Code sent to email', 'debug_code' => '000000']); 
    }
}

if ($action === 'forgot_verify') {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE email = ? AND code = ? AND expires_at > ?");
    $stmt->execute([$email, $code, time()]);
    
    if ($stmt->fetch()) {
        sendJson(['status' => 'success', 'message' => 'Code verified']);
    } else {
        sendJson(['status' => 'error', 'error' => 'Invalid or expired code']);
    }
}

if ($action === 'forgot_reset') {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? '';
    $pass = $input['password'] ?? '';
    
    // Verify again to be safe
    $stmt = $pdo->prepare("SELECT * FROM password_resets WHERE email = ? AND code = ? AND expires_at > ?");
    $stmt->execute([$email, $code, time()]);
    
    if ($stmt->fetch()) {
        $hash = password_hash($pass, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE users SET password = ? WHERE email = ?")->execute([$hash, $email]);
        $pdo->prepare("DELETE FROM password_resets WHERE email = ?")->execute([$email]);
        sendJson(['status' => 'success', 'message' => 'Password updated. Please login.']);
    } else {
        sendJson(['status' => 'error', 'error' => 'Invalid request']);
    }
}

// Authenticated Routes
if (!isset($_SESSION['user_id'])) {
    if ($action) sendJson(['status' => 'error', 'error' => 'Unauthorized']);
}

$userId = $_SESSION['user_id'];

if ($action === 'sync') {
    $forcePull = $input['force_pull'] ?? false;
    $clientData = $input['data'] ?? [];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $uRow = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($forcePull) {
        $data = $uRow['data_json'] ? json_decode($uRow['data_json'], true) : [];
        if(!$data) $data = [];
        
        $data['isPremium'] = ($uRow['is_premium'] == 1);
        $data['unlocked_features'] = $uRow['unlocked_features'] ? json_decode($uRow['unlocked_features'], true) : [];
        $data['currentUser'] = [
            'id' => $uRow['id'], 
            'email' => $uRow['email'], 
            'role' => $uRow['role']
        ];

        // Inject System Keys (OpenAI & Gemini & VAPID)
        $sys = $pdo->query("SELECT value FROM settings WHERE name = 'system_config'")->fetch();
        if($sys) {
            $sysConf = json_decode($sys['value'], true);
            if(!isset($data['settings'])) $data['settings'] = [];
            
            if(!empty($sysConf['openai_api_key'])) {
                $data['settings']['openaiApiKey'] = $sysConf['openai_api_key'];
            }
            if(!empty($sysConf['gemini_api_key'])) {
                $data['settings']['geminiApiKey'] = $sysConf['gemini_api_key'];
            }
            if(!empty($sysConf['vapid_public_key'])) {
                $data['settings']['vapidPublicKey'] = $sysConf['vapid_public_key'];
            }
        }

        sendJson(['status' => 'synced', 'data' => $data]);
    } else {
        // Push
        if (!empty($clientData)) {
            // Remove server-side keys before saving to avoid storing them in user blob
            if(isset($clientData['settings']['openaiApiKey'])) unset($clientData['settings']['openaiApiKey']);
            if(isset($clientData['settings']['geminiApiKey'])) unset($clientData['settings']['geminiApiKey']);
            if(isset($clientData['settings']['vapidPublicKey'])) unset($clientData['settings']['vapidPublicKey']);
            
            $json = json_encode($clientData);
            $stmt = $pdo->prepare("UPDATE users SET data_json = ? WHERE id = ?");
            $stmt->execute([$json, $userId]);
        }
        sendJson(['status' => 'synced']);
    }
}

if ($action === 'save_system_config') {
    if ($_SESSION['role'] !== 'admin') sendJson(['status' => 'error', 'error' => 'Forbidden']);
    $stmt = $pdo->prepare("INSERT OR REPLACE INTO settings (name, value) VALUES ('system_config', ?)");
    $stmt->execute([json_encode($input)]);
    sendJson(['status' => 'success']);
}
?>