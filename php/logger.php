<?php

class Logger
{
    // Define syslog severity levels as constants (as strings)
    const EMERG = 'EMERG';   // Emergency: system is unusable
    const ALERT = 'ALERT';   // Alert: action must be taken immediately
    const CRIT = 'CRIT';    // Critical: critical conditions
    const ERR = 'ERR';     // Error: error conditions
    const WARNING = 'WARNING'; // Warning: warning conditions
    const NOTICE = 'NOTICE';  // Notice: normal but significant condition
    const INFO = 'INFO';    // Informational: informational messages
    const DEBUG = 'DEBUG';   // Debug: debug-level messages

    /**
     * File to which logs will be written.
     * Adjust to your preferred log path and ensure correct permissions.
     */
    private static $logFile = '/tmp/pbx_api.log';

    /**
     * Writes a log message to disk. The format here uses the severity name
     * rather than a syslog priority number.
     *
     * Example line format:
     *   [SEVERITY] 2025-01-14 10:00:00 myhost myapp: This is a log message
     *
     * @param string $severity Severity name (e.g., "INFO", "ERR")
     * @param string $message The log message
     */
    private static function logMessage(string $severity, string $message): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $appName = 'myapp'; // You can make this dynamic if desired

        // Construct the log line
        $logLine = sprintf(
            "[%s] %s %s: %s\n",
            $severity,
            $timestamp,
            $appName,
            $message
        );

        // Append log to the file with an exclusive lock
        file_put_contents(self::$logFile, $logLine, FILE_APPEND | LOCK_EX);
    }

    /**
     * Public static methods for each syslog severity level.
     */
    public static function emerg(string $message): void
    {
        self::logMessage(self::EMERG, $message);
    }

    public static function alert(string $message): void
    {
        self::logMessage(self::ALERT, $message);
    }

    public static function crit(string $message): void
    {
        self::logMessage(self::CRIT, $message);
    }

    public static function err(string $message): void
    {
        self::logMessage(self::ERR, $message);
    }

    public static function warning(string $message): void
    {
        self::logMessage(self::WARNING, $message);
    }

    public static function notice(string $message): void
    {
        self::logMessage(self::NOTICE, $message);
    }

    public static function info(string $message): void
    {
        self::logMessage(self::INFO, $message);
    }

    public static function debug(string $message): void
    {
        self::logMessage(self::DEBUG, $message);
    }

    /**
     * Optionally allow changing the log file path at runtime.
     */
    public static function setLogFile(string $logFile): void
    {
        self::$logFile = $logFile;
    }
}