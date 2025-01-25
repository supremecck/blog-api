-- Blog gönderileri tablosu
CREATE TABLE blog_posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

-- Kullanıcı tablosu
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Token tablosu
CREATE TABLE api_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) DEFAULT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- API günlükleri tablosu
CREATE TABLE api_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    details TEXT DEFAULT NULL,
    timestamp DATETIME NOT NULL
);


-- Kullanıcı ekleme
INSERT INTO users (username, password_hash) VALUES
('admin', '$2y$10$4iGJ0XbMlnCXmTsjbrQv7eDnAgTaaEBJvH/rCw/gR96MoPwUYkz4W'), -- Şifre: admin123
('user1', '$2y$10$v/66PRQbPZ5p9SODLrLR6.bpHtNBtx8pdRb.z/FFY/zmWZAWMYmSC'); -- Şifre: user123

-- Blog gönderileri ekleme
INSERT INTO blog_posts (title, content, created_at) VALUES
('İlk Gönderi', 'Bu benim ilk gönderim.', NOW()),
('API Tanıtımı', 'Bu apiyi kullanarak CRUD işlemleri yapabilirsiniz.', NOW());

-- Örnek token (opsiyonel olarak otomatik oluşur)
INSERT INTO api_tokens (user_id, token, refresh_token, expires_at) VALUES
(1, 'sampleaccesstoken', 'samplerefreshtoken', DATE_ADD(NOW(), INTERVAL 1 HOUR));
