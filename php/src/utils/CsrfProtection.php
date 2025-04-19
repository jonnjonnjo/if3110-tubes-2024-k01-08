<?php

namespace src\utils;

class CsrfProtection
{
  /**
   * Generate a new CSRF token and store it in the session
   */
  public static function generateToken(): string
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }

    $token = bin2hex(random_bytes(32));

    // Store the token in the session
    $_SESSION['csrf_token'] = $token;

    return $token;
  }

  /**
   * Get the current CSRF token or generate a new one if not exists
   */
  public static function getToken(): string
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }

    // Check if token exists in session
    if (!isset($_SESSION['csrf_token'])) {
      return self::generateToken();
    }

    return $_SESSION['csrf_token'];
  }

  /**
   * Validate the CSRF token
   */
  public static function validateToken(?string $token): bool
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }

    // Check if token exists in session and matches
    if (!isset($_SESSION['csrf_token']) || $_SESSION['csrf_token'] !== $token) {
      return false;
    }

    return true;
  }

  /**
   * Generate HTML for a CSRF token field for form 
   */
  public static function csrfField(): string
  {
    $token = self::getToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
  }
}
