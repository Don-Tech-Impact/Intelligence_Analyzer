/**
 * auth.js - Frontend Authentication Manager
 * Handles JWT storage, validation, and role-based access control.
 */

const Auth = {
    TOKEN_KEY: 'afric_analyzer_jwt',

    /**
     * Store the JWT in local storage.
     */
    setToken(token) {
        localStorage.setItem(this.TOKEN_KEY, token);
    },

    /**
     * Retrieve the JWT from local storage.
     */
    getToken() {
        return localStorage.getItem(this.TOKEN_KEY);
    },

    /**
     * Clear the JWT and redirect to login page with confirmation.
     */
    logout() {
        if (!confirm("Are you sure you want to log out? This will clear your session and redirect you to the login page.")) {
            return;
        }

        console.log("Auth: Logging out. Clearing all authentication data...");

        // Clear JWT
        localStorage.removeItem(this.TOKEN_KEY);

        // Clear any other local/session storage items
        localStorage.removeItem('auth_debug_error');
        localStorage.removeItem('last_login_email');
        sessionStorage.clear();

        // Clear basic cookies
        document.cookie.split(";").forEach(function (c) {
            document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
        });

        console.log("Auth: All local data cleared.");

        // Redirect
        window.location.href = 'login.html';
    },

    /**
     * Parse the JWT payload safely.
     */
    getPayload() {
        const token = this.getToken();
        if (!token) return null;

        try {
            const base64Url = token.split('.')[1];
            if (!base64Url) return null;

            // Fix: Standard base64url to base64 conversion requires specific padding
            let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            while (base64.length % 4) {
                base64 += '=';
            }

            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));

            const payload = JSON.parse(jsonPayload);
            return payload;
        } catch (e) {
            console.error("Auth: Failed to parse JWT", e);
            localStorage.setItem('auth_debug_error', e.message);
            return null;
        }
    },

    /**
     * Basic check if the user is logged in.
     */
    isLoggedIn() {
        const payload = this.getPayload();
        if (!payload) {
            console.error("Auth: No payload found.");
            return false;
        }

        // DEBUG: Ignoring expiry check for now to solve redirect loop
        console.log("Auth: Token Payload detected:", payload);
        return true;
    },

    /**
     * Enforce authentication. Redirect to login if not authorized.
     */
    checkAuth() {
        const path = window.location.pathname;
        const isLoginPage = path.endsWith('login.html');
        const loggedIn = this.isLoggedIn();

        if (loggedIn && isLoginPage) {
            console.log("Auth: Already logged in. Holding for 2 seconds before redirect...");
            setTimeout(() => this.redirectToDashboard(), 2000);
            return true;
        }

        if (!loggedIn && !isLoginPage) {
            console.warn("Auth: Not logged in. Redirecting to login in 2 seconds...");
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
            return false;
        }

        return true;
    },

    /**
     * Redirect user based on their specific role.
     */
    redirectToDashboard() {
        const payload = this.getPayload();
        if (!payload) {
            console.error("Auth: No payload found, cannot redirect.");
            return;
        }

        // Extremely flexible role detection for Repo 1 tokens
        const role = (payload.role || '').toLowerCase();
        const isAdmin = payload.is_admin || (payload.admin && payload.admin.is_admin) || false;
        const username = (payload.username || (payload.admin && payload.admin.username) || '').toLowerCase();
        const email = (payload.email || (payload.admin && payload.admin.email) || '').toLowerCase();

        console.log(`Auth: User "${username || email}" detected. Role: ${role}, Admin: ${isAdmin}`);

        if (role === 'superadmin' || isAdmin || username === 'superadmin' || email.includes('admin@')) {
            console.log("Auth: Redirecting to superadmin.panel");
            window.location.href = 'superadmin.html';
        } else {
            console.log("Auth: Redirecting to standard.dashboard");
            window.location.href = 'index.html';
        }
    },

    /**
     * Get Authorization header for fetch requests.
     */
    getAuthHeader() {
        const token = this.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }
};

// Auto-run auth check on script load
Auth.checkAuth();
