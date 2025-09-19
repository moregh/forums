class CryptoUtils {
    // Generate a salt for password hashing
    static generateSalt() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Hash password with salt using Web Crypto API
    static async hashPassword(password, salt = null) {
        if (!salt) {
            salt = this.generateSalt();
        }
        
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        
        return { hash: hashHex, salt: salt };
    }

    // Verify password against stored hash and salt
    static async verifyPassword(password, storedHash, salt) {
        const { hash } = await this.hashPassword(password, salt);
        return hash === storedHash;
    }
}