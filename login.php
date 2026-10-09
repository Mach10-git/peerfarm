<?php
declare(strict_types=1);

function showMessage(int $status, string $message): void
{
    http_response_code($status);
    ?>
    <!DOCTYPE html>
    <html lang="uk">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PeerFarm - Вхід</title>
    </head>
    <body>
        <main>
            <p><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></p>
            <a href="login.html">Повернутися до входу</a>
        </main>
    </body>
    </html>
    <?php
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    showMessage(405, 'Цей запит не підтримується.');
}

$username = $_POST['username'] ?? null;
$password = $_POST['password'] ?? null;

if (!is_string($username) || !is_string($password) || $username === '' || $password === '') {
    showMessage(400, 'Введіть ім’я користувача та пароль.');
}

$dbHost = getenv('DB_HOST') ?: 'localhost';
$dbName = getenv('DB_NAME');
$dbUser = getenv('DB_USER');
$dbPassword = getenv('DB_PASS');

if (!$dbName || $dbUser === false || $dbPassword === false) {
    error_log('Login failed: database environment variables are not configured.');
    showMessage(500, 'Сервіс входу тимчасово недоступний.');
}

try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPassword,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );

    $statement = $pdo->prepare(
        'SELECT id, username, password_hash FROM users WHERE username = :username LIMIT 1'
    );
    $statement->execute(['username' => $username]);
    $user = $statement->fetch(PDO::FETCH_ASSOC);
} catch (PDOException $exception) {
    error_log('Login database error: ' . $exception->getMessage());
    showMessage(500, 'Сервіс входу тимчасово недоступний.');
}

if (!$user) {
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    if ($passwordHash === false) {
        error_log('Login failed: password hashing failed.');
        showMessage(500, 'Сервіс входу тимчасово недоступний.');
    }

    try {
        $statement = $pdo->prepare(
            'INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)'
        );
        $statement->execute([
            'username' => $username,
            'password_hash' => $passwordHash,
        ]);
        $user = [
            'id' => $pdo->lastInsertId(),
            'username' => $username,
        ];
    } catch (PDOException $exception) {
        if (($exception->errorInfo[1] ?? null) !== 1062) {
            error_log('Account creation error: ' . $exception->getMessage());
            showMessage(500, 'Сервіс входу тимчасово недоступний.');
        }

        try {
            $statement = $pdo->prepare(
                'SELECT id, username, password_hash FROM users WHERE username = :username LIMIT 1'
            );
            $statement->execute(['username' => $username]);
            $user = $statement->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $lookupException) {
            error_log('Login database error: ' . $lookupException->getMessage());
            showMessage(500, 'Сервіс входу тимчасово недоступний.');
        }
    }
}

if (!$user || !password_verify($password, $user['password_hash'] ?? '')) {
    showMessage(401, 'Неправильне ім’я користувача або пароль.');
}

session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Lax',
]);
session_start();
session_regenerate_id(true);
$_SESSION['user_id'] = $user['id'];
$_SESSION['username'] = $user['username'];

header('Location: index.html', true, 303);
exit;
