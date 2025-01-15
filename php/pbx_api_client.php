<?php

require_once('logger.php');

/**
 * This is an example API client for interacting the PBX API. Based on rate limiting information returned in the
 * response headers, the implementation will sleep only when necessary, to avoid violating the rate limit and receiving
 * a 429 response. This is a naive implementation that assumes all interaction with the PBX API flows through one
 * instance of this class for the purposes of demonstrating the fundamentals, such has how to parse the response
 * headers. A more comprehensive solution would use common storage such as database or cache to store rate limit tracking
 * to synchronize across multiple instances of this class when necessary. 
 *
 */
class ApiClient
{

    protected $resellerId;
    protected $clientId;
    protected $clientSecret;
    protected $username;
    protected $password;
    protected $accessTokenExpiresAt;
    protected $accessToken;
    protected $refreshToken;
    protected $rateLimitRefreshTime;

    /**
     * @param string $resellerId
     * @param string $clientId
     * @param string $clientSecret
     * @param string $username
     * @param string $password
     */
    public function __construct($resellerId, $clientId, $clientSecret, $username, $password)
    {
        $this->resellerId = $resellerId;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->username = $username;
        $this->password = $password;
    }

    public function __destruct()
    {
        $this->revokeAccessToken();
    }

    /**
     * @return string
     */
    protected function getBaseUri()
    {
        return "https://{$this->resellerId}-hpbx.dashmanager.com/ns-api";
    }

    /**
     * @param string $user
     * @param string $domain
     * @return stdClass
     */
    public function getSubscriber($user, $domain)
    {
        $data['object'] = 'subscriber';
        $data['action'] = 'read';
        $data['user'] = $user;
        $data['domain'] = $domain;

        $subscribers = $this->request($data);

        if (empty($subscribers)) {
            throw new Exception("Could not find subscriber `{$user}@{$domain}`");
        }

        return current($subscribers);
    }


    /**
     * Returns a valid access token, generating the token if necessary
     *
     * @return string
     */
    private function getAccessToken()
    {
        if (is_null($this->accessToken) || $this->accessTokenExpiresAt < new DateTime()) {
            Logger::info('Requesting new NSAPI token.');


            $data = [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'password',
                'username' => $this->username,
                'password' => $this->password,
            ];

            $response = $this->authRequest($data, '/oauth2/token');
            $this->accessToken = $response->access_token;
            $this->refreshToken = $response->refresh_token;

            $date = new DateTime();
            $this->accessTokenExpiresAt = $date->add(new DateInterval("PT{$response->expires_in}S"));
        }

        return $this->accessToken;
    }

    /**
     * Returns true if there was an active access token that was revoked, otherwise returns false
     *
     * @return bool
     */
    private function revokeAccessToken()
    {
        if (!is_null($this->accessToken) && $this->accessTokenExpiresAt > new DateTime()) {
            Logger::info('Revoking NSAPI token.');

            $data['client_id'] = $this->clientId;
            $data['client_secret'] = $this->clientSecret;
            $data['token'] = $this->accessToken;

            $this->authRequest($data, '/oauth2/revoke');
            $this->accessToken = null;
            $this->refreshToken = null;
            return true;
        }

        return false;
    }


    /**
     * @param array $data
     * @return mixed
     * @throws RuntimeException
     */
    private function request($data = [])
    {
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $this->getAccessToken(),
            'Accept: application/json',
        ]);

        return json_decode($this->sendHttpRequest($handle, $data));
    }

    /**
     * @param array $data
     * @param string $path
     * @return stdClass
     */
    private function authRequest($data, $path)
    {
        $handle = curl_init();

        $result = $this->sendHttpRequest($handle, $data, $path);
        return json_decode($result);
    }

    /**
     * @param $handle
     * @param array $data
     * @param string $path
     * @param int $attemptCounter
     * @return string
     * @throws RuntimeException
     */
    private function sendHttpRequest($handle, $data = array(), $path = '/', $attemptCounter = 1)
    {
        if($attemptCounter > 3) {
            throw new Exception('PBX API request retry limit');
        }

        $url = $this->getBaseUri() . $path;
        $body = http_build_query($data);

        curl_setopt($handle, CURLOPT_URL, $url);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($handle, CURLOPT_FOLLOWLOCATION, 0);
        curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($handle, CURLOPT_CONNECTTIMEOUT, 60);
        curl_setopt($handle, CURLOPT_TIMEOUT, 60);
        curl_setopt($handle, CURLOPT_POST, true);
        curl_setopt($handle, CURLOPT_POSTFIELDS, $body);

        // Capture headers in a callback
        $responseHeaders = [];
        curl_setopt($handle, CURLOPT_HEADERFUNCTION, function ($ch, $header) use (&$responseHeaders) {
            $len = strlen($header);
            $headerParts = explode(':', $header, 2);
            if (count($headerParts) === 2) {
                $name = trim($headerParts[0]);
                $value = trim($headerParts[1]);
                // Some headers can occur multiple times
                if (!isset($responseHeaders[$name])) {
                    $responseHeaders[$name] = $value;
                } else {
                    // If needed, append or store an array
                    $responseHeaders[$name] .= ', ' . $value;
                }
            }
            return $len;
        });

        Logger::debug('Making HTTP request.', ['url' => $url, 'body' => $body]);

        if(!is_null($this->rateLimitRefreshTime) && $this->rateLimitRefreshTime > time()) {
            $sleepSeconds = $this->rateLimitRefreshTime - time();
            Logger::debug("Sleeping $sleepSeconds seconds to respect api rate limit");
            sleep($sleepSeconds);
            $this->rateLimitRefreshTime = null;
        }

        $result = curl_exec($handle);

        Logger::debug('Received HTTP response.', ['code' => curl_getinfo($handle, CURLINFO_HTTP_CODE), 'response' => $result]);

        if ($result === false) {
            Logger::err('PBX API curl error.', ['error' => curl_error($handle)]);
            throw new RuntimeException('PBX API request failed with reason(s): ' . curl_error($handle));
        }

        $httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        $sleepSeconds = $this->calculateSleepFromRateLimitHeaders($responseHeaders);
        if($sleepSeconds > 0) {
            $this->rateLimitRefreshTime = time() + $sleepSeconds;
        }

        // If 429 is received, handle it by sleeping until we can retry
        if ($httpCode === 429) {
            return $this->sendHttpRequest($handle, $data, $path, ++$attemptCounter);
        }

        if (curl_getinfo($handle, CURLINFO_HTTP_CODE) < 200 || curl_getinfo($handle, CURLINFO_HTTP_CODE) > 299) {
            throw new RuntimeException('PBX API request returned non 200 response `' . curl_getinfo($handle, CURLINFO_HTTP_CODE) . '``.');
        }

        curl_close($handle);
        return $result;
    }

    /**
     * If we got a 429, use the RateLimit headers to decide how long to sleep.
     * We will parse out the minimal `t` among all exhausted policies or just pick the biggest.
     *
     * @param array $headers The response headers
     * @return int   seconds to sleep
     */
    private function calculateSleepFromRateLimitHeaders(array $headers): int
    {
        if (!isset($headers['RateLimit'])) {
            return 0;
        }

        $sleepSeconds = 0;

        $policies = $this->parseRateLimitHeader($headers['RateLimit']);

        // Find the policy/policies with 0 remaining; pick the largest reset.
        foreach ($policies as $p) {
            if ($p['remaining'] <= 0) {
                $sleepSeconds = max($sleepSeconds, $p['reset']);
            }
        }

        return $sleepSeconds;
    }

    /**
     * Parses a RateLimit header string into an array of policies.
     *
     * Example input:
     *  "subscriber_minute";r=59;t=31;pk=:MTExODNA..., "subscriber_hour";r=1799;t=331;pk=...
     *
     * Return example:
     *  [
     *    [
     *      'policy' => 'subscriber_minute',
     *      'remaining' => 59,
     *      'reset' => 31,
     *      'pk' => ':MTExODNA...'
     *    ],
     *    [
     *      'policy' => 'subscriber_hour',
     *      'remaining' => 1799,
     *      'reset' => 331,
     *      'pk' => ':MTExODNA...'
     *    ]
     *  ]
     */
    private function parseRateLimitHeader(string $rateLimitHeader): array
    {
        $policies = [];

        // The header can contain multiple policy segments, separated by commas:
        // "subscriber_minute";r=59;t=31;pk=..., "client_minute";r=89;t=31;pk=...
        $segments = explode(',', $rateLimitHeader);

        foreach ($segments as $segment) {
            // Trim spaces
            $segment = trim($segment);
            // Typical segment looks like: `"subscriber_minute";r=59;t=31;pk=:base64:`
            //
            // We'll parse out: policy=subscriber_minute, r=59, t=31, pk=:base64:
            // One approach is to use a regex or simple string ops. Let's do simple string ops.

            // 1) Split on the first semicolon to separate the policy name from the rest
            //    e.g., '"subscriber_minute"' vs 'r=59;t=31;pk=:base64:'
            $parts = explode(';', $segment);
            if (count($parts) < 2) {
                continue;
            }

            // The first part might be quoted, so let's remove quotes
            $policyName = trim($parts[0], "\"");

            $remaining = null;
            $reset = null;
            $pk = null;

            // Now parse the subsequent kv pairs
            for ($i = 1; $i < count($parts); $i++) {
                $kv = explode('=', $parts[$i]);
                if (count($kv) !== 2) {
                    continue;
                }

                $key = $kv[0];
                $value = $kv[1];

                // Remove possible quotes
                $value = trim($value, "\"");

                switch ($key) {
                    case 'r':
                        $remaining = (int) $value;
                        break;
                    case 't':
                        $reset = (int) $value;
                        break;
                    case 'pk':
                        $pk = $value;
                        break;
                }
            }

            // Add to array if we got the important stuff
            if ($policyName && $remaining !== null && $reset !== null) {
                // policyName might still have quotes around it if the server used them
                $policyName = trim($policyName, "\"");

                $policies[] = [
                    'policy' => $policyName,
                    'remaining' => $remaining,
                    'reset' => $reset,
                    'pk' => $pk,
                ];
            }
        }

        return $policies;
    }

}
