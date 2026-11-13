import http from 'node:http';

const port = Number(process.env.PORT || 39911);
let balance = 100;

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    let body = {};
    try { body = JSON.parse(raw || '{}'); } catch {}

    if (req.method === 'POST' && req.url === '/api/v1/checkout/withdraw') {
      const amt = Number(body.amount || 0);
      // Simulated async DB check-then-act without transaction lock!
      const current = balance;
      await new Promise((r) => setTimeout(r, 15));
      if (current >= amt && amt > 0) {
        balance = current - amt;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: true, balance }));
      }
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: false, error: 'insufficient_balance', balance }));
    }

    if (req.method === 'POST' && req.url === '/api/v1/checkout/deposit') {
      if (!req.headers.authorization) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: false, error: 'unauthorized' }));
      }
      balance += Number(body.amount || 0);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, balance }));
    }

    res.writeHead(404);
    res.end();
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`fixture listening on 127.0.0.1:${port}`);
});
