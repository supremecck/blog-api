<?php
$db_name="blog_api";
$username = "root";
$password = "";

$dsn = "mysql:host=localhost;dbname=$db_name;charset=utf8";

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];
$conn = new PDO($dsn, $username, $password, $options);

function respond($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function logRequest($action, $status, $details = null) {
    global $conn;
    $stmt = $conn->prepare("INSERT INTO api_logs (action, status, details, timestamp) VALUES (?, ?, ?, NOW())");
    $stmt->execute([$action, $status, $details]);
}


function rateLimit($ip, $limit = 100) {
    global $conn;
    $stmt = $conn->prepare("SELECT COUNT(*) as request_count FROM api_logs WHERE ip = ? AND timestamp > (NOW() - INTERVAL 1 HOUR)");
    $stmt->execute([$ip]);
    $result = $stmt->fetch();

    if ($result['request_count'] >= $limit) {
        respond(["error" => "Rate limit exceeded", "message" => "Saatlik istek limiti aşıldı"], 429);
    }
}

function verifyToken($authorizationHeader) {
    global $conn;
    if (!$authorizationHeader || !str_starts_with($authorizationHeader, 'Bearer ')) {
        respond(["error" => "Unauthorized", "message" => "Token eksik veya yanlış formatta"], 401);
    }

    $token = substr($authorizationHeader, 7);

    $stmt = $conn->prepare("SELECT * FROM api_tokens WHERE token = ? AND expires_at > NOW()");
    $stmt->execute([$token]);
    $tokenData = $stmt->fetch();

    if (!$tokenData) {
        respond(["error" => "Unauthorized", "message" => "Geçersiz veya süresi dolmuş token"], 401);
    }
}

function generateToken($userId) {
    global $conn;
    $token = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

    $stmt = $conn->prepare("INSERT INTO api_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
    $stmt->execute([$userId, $token, $expiresAt]);

    return $token;
}

function handleTokenRefresh($refreshToken) {
    global $conn;
    $stmt = $conn->prepare("SELECT user_id FROM api_tokens WHERE refresh_token = ?");
    $stmt->execute([$refreshToken]);
    $user = $stmt->fetch();

    if ($user) {
        return generateToken($user['user_id']);
    } else {
        respond(["error" => "Unauthorized", "message" => "Geçersiz yenileme tokenı"], 401);
    }
}

function authenticateUser($username, $password) {
    global $conn;
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        $accessToken = generateToken($user['id']);
        $refreshToken = bin2hex(random_bytes(32));

        $stmt = $conn->prepare("UPDATE api_tokens SET refresh_token = ? WHERE user_id = ?");
        $stmt->execute([$refreshToken, $user['id']]);

        return [
            "access_token" => $accessToken,
            "refresh_token" => $refreshToken
        ];
    } else {
        respond(["error" => "Unauthorized", "message" => "Kullanıcı adı veya şifre hatalı"], 401);
    }
}

function validateJsonSchema($data, $schema) {
    foreach ($schema->required as $field) {
        if (!isset($data[$field])) {
            respond([
                "error" => "Invalid JSON",
                "message" => "Eksik alan: $field"
            ], 400);
        }
    }

    foreach ($schema->properties as $field => $rules) {
        if (isset($data[$field]) && $rules['type'] !== gettype($data[$field])) {
            respond([
                "error" => "Invalid JSON",
                "message" => "$field alanı " . $rules['type'] . " türünde olmalı"
            ], 400);
        }
    }
}

function handleRequest($method, $action) {
    global $conn;
    $headers = getallheaders();
    $authorizationHeader = $headers['Authorization'] ?? null;
    
    $routes = [
        'GET' => [
            'fetch' => function () use ($conn) {
                $page = $_GET['page'] ?? 1;
                $limit = $_GET['limit'] ?? 10;
                $offset = ($page - 1) * $limit;

                $stmt = $conn->prepare("SELECT * FROM blog_posts LIMIT ? OFFSET ?");
                $stmt->bindValue(1, (int)$limit, PDO::PARAM_INT);
                $stmt->bindValue(2, (int)$offset, PDO::PARAM_INT);
                $stmt->execute();
                $posts = $stmt->fetchAll();

                logRequest('fetch', 'success', "Page: $page, Limit: $limit");
                respond($posts);
            },
            'single' => function () use ($conn) {
                $id = $_GET['id'] ?? null;
                if (!$id) {
                    respond(["error" => "Invalid Request", "message" => "Eksik ID parametresi"], 400);
                }

                $stmt = $conn->prepare("SELECT * FROM blog_posts WHERE id = ?");
                $stmt->execute([$id]);
                $post = $stmt->fetch();

                if ($post) {
                    logRequest('single', 'success', "ID: $id");
                    respond($post);
                } else {
                    respond(["error" => "Not Found", "message" => "Gönderi bulunamadı"], 404);
                }
            }
        ],
        'POST' => [
            'login' => function () {
                $data = json_decode(file_get_contents('php://input'), true);
                if (!isset($data['username']) || !isset($data['password'])) {
                    respond(["error" => "Invalid Request", "message" => "Kullanıcı adı ve şifre gereklidir"], 400);
                }

                $tokens = authenticateUser($data['username'], $data['password']);
                respond($tokens);
            },
            'token_refresh' => function () {
                $data = json_decode(file_get_contents('php://input'), true);
                if (!isset($data['refresh_token'])) {
                    respond(["error" => "Invalid Request", "message" => "Yenileme tokenı gereklidir"], 400);
                }

                $newToken = handleTokenRefresh($data['refresh_token']);
                respond(["access_token" => $newToken]);
            },
            'create' => function () use ($conn, $authorizationHeader) {
                verifyToken($authorizationHeader);
                $data = json_decode(file_get_contents('php://input'), true);

                $schema = (object) [
                    "type" => "object",
                    "properties" => ["title" => ["type" => "string"], "content" => ["type" => "string"]],
                    "required" => ["title", "content"]
                ];

                validateJsonSchema($data, $schema);

                $stmt = $conn->prepare("INSERT INTO blog_posts (title, content, created_at) VALUES (?, ?, NOW())");
                $stmt->execute([$data['title'], $data['content']]);

                logRequest('create', 'success', json_encode($data));
                respond(["message" => "Gönderi başarıyla oluşturuldu"]);
            }
        ],
        'PUT' => [
            'update' => function () use ($conn, $authorizationHeader) {
                verifyToken($authorizationHeader);
                $data = json_decode(file_get_contents('php://input'), true);

                $stmt = $conn->prepare("UPDATE blog_posts SET title = ?, content = ? WHERE id = ?");
                $stmt->execute([$data['title'], $data['content'], $data['id']]);

                logRequest('update', 'success', json_encode($data));
                respond(["message" => "Gönderi başarıyla güncellendi"]);
            }
        ],
        'DELETE' => [
            'delete' => function () use ($conn, $authorizationHeader) {
                verifyToken($authorizationHeader);
                $data = json_decode(file_get_contents('php://input'), true);

                $stmt = $conn->prepare("DELETE FROM blog_posts WHERE id = ?");
                $stmt->execute([$data['id']]);

                logRequest('delete', 'success', json_encode($data));
                respond(["message" => "Gönderi başarıyla silindi"]);
            }
        ]
    ];

    if (isset($routes[$method][$action])) {
        $routes[$method][$action]();
    } else {
        logRequest($action, 'failure', null);
        respond(["error" => "Invalid Request", "message" => "Geçersiz istek"], 400);
    }
}

try {
    handleRequest($_SERVER['REQUEST_METHOD'], $_GET['action'] ?? '');
} catch (Exception $e) {
    logRequest('error', 'failure', $e->getMessage());
    respond(["error" => "Server Error", "message" => $e->getMessage()], 500);
}
