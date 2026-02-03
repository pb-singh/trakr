<?php
// Retrieve token from URL for server-side validation/rendering if needed
$token = $_GET['token'] ?? '';
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraKr | Reset Password</title>
    <link rel="icon" href="assets/trakr-logo.png" type="image/png">
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: '#09090b',
                        surface: '#18181b',
                        primary: '#6366f1'
                    },
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- FontAwesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Alpine.js -->
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.13.3/dist/cdn.min.js"></script>
    
    <style>
        body { font-family: 'Inter', sans-serif; }
        [x-cloak] { display: none !important; }
    </style>
</head>
<body class="bg-dark min-h-screen flex items-center justify-center p-4" x-data="resetApp()" x-init="init()" x-cloak>
    
    <div class="w-full max-w-md bg-surface p-8 rounded-3xl border border-gray-800 shadow-2xl relative overflow-hidden">
        
        <!-- Background Decor -->
        <div class="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 rounded-full blur-3xl -mr-16 -mt-16 pointer-events-none"></div>
        <div class="absolute bottom-0 left-0 w-32 h-32 bg-rose-500/10 rounded-full blur-3xl -ml-16 -mb-16 pointer-events-none"></div>

        <div class="relative z-10 text-center">
            <div class="w-16 h-16 bg-indigo-500/10 text-indigo-500 rounded-2xl flex items-center justify-center mx-auto mb-6 text-2xl shadow-lg shadow-indigo-500/20">
                <i class="fa-solid fa-lock-open"></i>
            </div>
            
            <h2 class="text-2xl font-bold text-white mb-2">Reset Password</h2>
            
            <!-- Conditional Header Text -->
            <p class="text-gray-400 text-sm mb-8" x-show="!success && token">
                Securely update your account credentials.
            </p>

            <!-- Status Messages -->
            <div x-show="error" x-transition class="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-xs font-bold flex items-center justify-center gap-2">
                <i class="fa-solid fa-circle-exclamation"></i> <span x-text="error"></span>
            </div>
            <div x-show="success" x-transition class="mb-4 p-3 bg-green-500/10 border border-green-500/20 rounded-xl text-green-400 text-xs font-bold flex items-center justify-center gap-2">
                <i class="fa-solid fa-check-circle"></i> <span x-text="success"></span>
            </div>

            <!-- Missing Token State -->
            <div x-show="!token && !success" class="text-center py-4">
                <p class="text-gray-500 text-sm mb-4">Invalid or missing reset token.</p>
                <a href="index.html" class="inline-block px-6 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-white text-xs font-bold transition-colors">Return to Login</a>
            </div>

            <!-- Reset Form -->
            <form @submit.prevent="submitReset" x-show="!success && token" class="space-y-4">
                <div class="text-left">
                    <label class="text-xs font-bold text-gray-500 uppercase ml-1 mb-1 block">New Password</label>
                    <input type="password" x-model="password" class="w-full bg-dark border border-gray-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all placeholder-gray-700" placeholder="••••••••" required>
                </div>
                <div class="text-left">
                    <label class="text-xs font-bold text-gray-500 uppercase ml-1 mb-1 block">Confirm Password</label>
                    <input type="password" x-model="confirmPassword" class="w-full bg-dark border border-gray-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all placeholder-gray-700" placeholder="••••••••" required>
                </div>
                <button type="submit" :disabled="loading" class="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-indigo-600/20 disabled:opacity-50 disabled:cursor-not-allowed transform active:scale-95">
                    <span x-show="!loading">Reset Password</span>
                    <span x-show="loading"><i class="fa-solid fa-circle-notch animate-spin"></i> Updating...</span>
                </button>
            </form>

            <!-- Success Action -->
            <div x-show="success" class="mt-6">
                <p class="text-gray-400 text-sm mb-6">Your password has been successfully updated.</p>
                <a href="index.html" class="block w-full py-3 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-xl transition-colors border border-gray-700">
                    Back to Login
                </a>
            </div>
        </div>
    </div>

    <script>
        function resetApp() {
            return {
                token: '<?php echo htmlspecialchars($token); ?>',
                password: '',
                confirmPassword: '',
                loading: false,
                error: '',
                success: '',
                
                init() {
                    // Fallback to URL params if PHP echo fails or for consistency
                    if(!this.token) {
                        const params = new URLSearchParams(window.location.search);
                        this.token = params.get('token');
                    }
                },

                async submitReset() {
                    if (this.password.length < 6) {
                        this.error = "Password must be at least 6 characters";
                        return;
                    }
                    if (this.password !== this.confirmPassword) {
                        this.error = "Passwords do not match";
                        return;
                    }
                    
                    this.loading = true;
                    this.error = '';
                    
                    try {
                        const res = await fetch('api.php?action=reset_password', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token: this.token,
                                password: this.password
                            })
                        });
                        
                        const data = await res.json();
                        
                        if (data.status === 'success') {
                            this.success = data.message;
                        } else {
                            this.error = data.error || 'Reset failed';
                        }
                    } catch (e) {
                        this.error = 'Network error occurred. Please try again.';
                    } finally {
                        this.loading = false;
                    }
                }
            }
        }
    </script>
</body>
</html>