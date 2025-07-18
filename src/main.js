import http from 'http';
import https from 'https';
import net from 'net';
import { WebSocketServer, createWebSocketStream } from 'ws';
import express from 'express';
import auth from "basic-auth";
import { exec } from 'child_process';

const web_username = process.env.WEB_USERNAME || "admin";
const web_password = process.env.WEB_PASSWORD || "password";

const userID = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const listenPort = process.env.PORT || 7860;
const dohServer = process.env.DOH_SERVER || 'https://dns.nextdns.io/7df33f';

(async () => {
  exec(`chmod +x nezha_agent && ./nezha_agent`, (error, stdout, stderr) => {
    // No output here
  });
})();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

async function resolveDomainViaDoH(domain) {
  return new Promise((resolve, reject) => {
    const url = `${dohServer}?name=${encodeURIComponent(domain)}&type=A`;
    https.get(url, {
      headers: {
        'Accept': 'application/dns-json'
      }
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.Answer && response.Answer.length > 0) {
            const answer = response.Answer.find(a => a.type === 1);
            if (answer) return resolve(answer.data);
            reject(new Error('No A record found'));
          } else {
            reject(new Error('DNS query failed'));
          }
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', (err) => reject(err));
  });
}

function parseAddress(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  let targetHost;
  if (ATYP === 1) {
    const ipBytes = msg.slice(offset, offset + 4);
    offset += 4;
    targetHost = Array.from(ipBytes).join('.');
  } else if (ATYP === 2) {
    const len = msg.readUInt8(offset++);
    targetHost = msg.slice(offset, offset + len).toString('utf8');
    offset += len;
  } else if (ATYP === 3) {
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    targetHost = segments.join(':');
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
  return { ATYP, targetHost, offset };
}

wss.on('connection', (ws) => {
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const interval = setInterval(() => {
    if (!ws.isAlive) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', async (msg) => {
    let socket = null;
    let duplex = null;
    try {
      if (msg.length < 18) {
         ws.close();
         return;
      }

      const receivedID = msg.slice(1, 17).toString('hex');
      if (receivedID !== userID) {
        ws.close();
        return;
      }

      let offset = msg.readUInt8(17) + 19;
      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let targetHost, ATYP;
      ({ ATYP, targetHost, offset } = parseAddress(msg, offset));

      if (ATYP === 2) {
        try {
          targetHost = await resolveDomainViaDoH(targetHost);
        } catch (err) {
          ws.close();
          return;
        }
      }

      ws.send(Buffer.from([msg[0], 0]));

      duplex = createWebSocketStream(ws);
      socket = net.connect({
        host: targetHost,
        port: targetPort
      }, () => {
        if (msg.length > offset) {
           socket.write(msg.slice(offset));
        }
        if (duplex && !duplex.destroyed && socket && !socket.destroyed) {
           duplex.pipe(socket).pipe(duplex);
        }
      });

      socket.on('error', () => {
        if (socket && !socket.destroyed) socket.destroy();
        if (duplex && !duplex.destroyed) duplex.destroy();
      });

      duplex.on('error', () => {
        if (socket && !socket.destroyed) socket.destroy();
        if (duplex && !duplex.destroyed) duplex.destroy();
      });

      duplex.on('close', () => {
         if (socket && !socket.destroyed) socket.destroy();
      });

      ws.on('close', () => {
         if (socket && !socket.destroyed) socket.destroy();
         if (duplex && !duplex.destroyed) duplex.destroy();
      });

    } catch (err) {
      if (socket && !socket.destroyed) socket.destroy();
      if (duplex && !duplex.destroyed) duplex.destroy();
      if (ws.readyState === ws.OPEN) ws.close();
    }
  });

  ws.on('error', () => {
      if (ws.readyState === ws.OPEN) ws.close();
  });
});

app.use((req, res, next) => {
  const user = auth(req);
  if (user && user.name === web_username && user.pass === web_password) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Node"');
  res.status(401).send();
});

app.get('/shell/:command', (req, res) => {
  const command = req.params.command.replace(/_/g, ' ');
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      res.status(500).send(`Error: ${error.message}`);
      return;
    }
    res.type('text/plain').send(stdout + stderr);
  });
});

app.get('*', (req, res) => {
  const scheme = req.protocol;
  let host = req.get('host');
  let portNum = scheme === 'https' ? 443 : 80;
  const path = req.path;

  if (host.includes(':')) {
    [host, portNum] = host.split(':');
  }

  const link = scheme === 'https'
    ? `pler://${userID}@${host}:${portNum}?path=${path}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#node-pler`
    : `pler://${userID}@${host}:${portNum}?type=ws&encryption=none&flow=&host=${host}&path=${path}#node-pler`;

  res.send(`<html><body><pre>${link}</pre></body></html>`);
});

server.listen(listenPort, () => {
  // Server is running, but no output here
});
