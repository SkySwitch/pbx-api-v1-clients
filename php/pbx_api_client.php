<?php

require_once('logger.php');

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

        return json_decode($this->performRequest($handle, $data));
    }

    /**
     * @param array $data
     * @param string $path
     * @return stdClass
     */
    private function authRequest($data, $path)
    {
        $handle = curl_init();

        $result = $this->performRequest($handle, $data, $path);
        return json_decode($result);
    }

    /**
     * @param $handle
     * @param array $data
     * @param string $path
     * @return string
     * @throws RuntimeException
     */
    private function performRequest($handle, $data = array(), $path = '/')
    {
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

        curl_setopt($handle, CURLINFO_HEADER_OUT, true);

        Logger::debug('Making HTTP request.', ['url' => $url, 'body' => $body]);

        $result = curl_exec($handle);

        Logger::debug('Received HTTP response.', ['code' => curl_getinfo($handle, CURLINFO_HTTP_CODE), 'response' => $result]);

        if ($result === false) {
            Logger::err('PBX API curl error.', ['error' => curl_error($handle)]);
            throw new RuntimeException('PBX API request failed with reason(s): ' . curl_error($handle));
        } else if (curl_getinfo($handle, CURLINFO_HTTP_CODE) < 200 || curl_getinfo($handle, CURLINFO_HTTP_CODE) > 299) {
            throw new RuntimeException('PBX API request returned non 200 response `' . curl_getinfo($handle, CURLINFO_HTTP_CODE) . '``.');
        }

        curl_close($handle);
        return $result;
    }

}
