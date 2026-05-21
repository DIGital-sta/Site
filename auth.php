<?php

session_start();

define('USERS_FILE', __DIR__ . '/users.json');



function getUsers(): array {
    if (!file_exists(USERS_FILE)) return [];
    $json = file_get_contents(USERS_FILE);
    $data = json_decode($json, true);
    return is_array($data) ? $data : [];
}

function saveUsers(array $users): void {
    file_put_contents(USERS_FILE, json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}



function isLoggedIn(): bool {
    return isset($_SESSION['user']);
}

function isAdmin(): bool {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function currentUser(): ?string {
    return $_SESSION['user'] ?? null;
}

function currentUserName(): ?string {
    return $_SESSION['display_name'] ?? $_SESSION['user'] ?? null;
}


function login(string $username, string $password): bool {
  
    if ($username === 'admin' && $password === 'admin') {
        $_SESSION['user']         = 'admin';
        $_SESSION['role']         = 'admin';
        $_SESSION['display_name'] = 'Адмін';
        return true;
    }

  
    $users = getUsers();
    foreach ($users as $u) {
        if (
            strtolower($u['username']) === strtolower($username) &&
            password_verify($password, $u['password_hash'])
        ) {
            $_SESSION['user']         = $u['username'];
            $_SESSION['role']         = $u['role'] ?? 'user';
            $_SESSION['display_name'] = $u['display_name'] ?? $u['username'];
            return true;
        }
    }
    return false;
}


function register(string $username, string $email, string $password, string $displayName = ''): array {

    if (strlen($username) < 3) {
        return ['success' => false, 'message' => 'Логін має містити щонайменше 3 символи.'];
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Невірний формат email.'];
    }
    if (strlen($password) < 6) {
        return ['success' => false, 'message' => 'Пароль має містити щонайменше 6 символів.'];
    }

 
    if (strtolower($username) === 'admin') {
        return ['success' => false, 'message' => 'Цей логін зарезервований.'];
    }

    $users = getUsers();

    
    foreach ($users as $u) {
        if (strtolower($u['username']) === strtolower($username)) {
            return ['success' => false, 'message' => 'Користувач із таким логіном вже існує.'];
        }
        if (strtolower($u['email']) === strtolower($email)) {
            return ['success' => false, 'message' => 'Цей email вже зареєстрований.'];
        }
    }

    
    $users[] = [
        'username'      => $username,
        'email'         => strtolower($email),
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'display_name'  => $displayName !== '' ? $displayName : $username,
        'role'          => 'user',
        'created_at'    => date('Y-m-d H:i:s'),
    ];
    saveUsers($users);

    return ['success' => true, 'message' => 'Реєстрація успішна!'];
}



function logout(): void {
    session_unset();
    session_destroy();
}



function requireAuth(): void {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

function requireAdmin(): void {
    requireAuth();
    if (!isAdmin()) {
        header('Location: index.php');
        exit;
    }
}
?>
