// ---------------------------------------------------------------- Oracle A1 launcher (3.1.0)
// The database is moving to an Always Free Oracle Ampere A1 server (Neon's Free plan allows 5 GB a month of query
// results and the collector reads about 270 MB a day). Free A1 capacity in Chicago is released only when another
// tenant deletes a server, so this job asks for one in every 15-minute slot until a launch succeeds, then stops.
// The API signing key is generated here on first use: the private half stays in this project's private bucket and only
// the public half is shown (for the operator to register on a dedicated Oracle user that may only manage instances).
// Settings (tenancy, user, subnet, image, availability domains, shapes, the server's SSH public key and the key of its
// bootstrap script) are in ops/oci-a1.json; none of them is a secret.
const OCI = { KEY: 'secrets/oci-launcher.pem', CONF: 'ops/oci-a1.json', STATE: 'oci:a1', TIMEOUT_MS: 30000 };

export async function ociKey() {
  let o = await s3Get(OCI.KEY);
  if (!o) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    await s3Put(OCI.KEY, Buffer.from(privateKey), 'application/x-pem-file');
    o = { buf: Buffer.from(privateKey) };
  }
  const priv = createPrivateKey(o.buf.toString('utf8')), pub = createPublicKey(priv);
  const der = pub.export({ type: 'spki', format: 'der' });
  return { priv, pub: pub.export({ type: 'spki', format: 'pem' }), fingerprint: createHash('md5').update(der).digest('hex').match(/../g).join(':') };
}

// Oracle's HTTP signature (draft-cavage, rsa-sha256): (request-target), date and host always; the body's digest, type
// and length on requests that carry one.
export function ociSignedHeaders({ method, url, body = null, keyId, priv, date = new Date().toUTCString() }) {
  const u = new URL(url), h = { date, host: u.host }, names = ['(request-target)', 'date', 'host'];
  if (body != null) {
    h['content-type'] = 'application/json'; h['content-length'] = String(Buffer.byteLength(body));
    h['x-content-sha256'] = createHash('sha256').update(body).digest('base64');
    names.push('x-content-sha256', 'content-type', 'content-length');
  }
  const signing = names.map((n) => (n === '(request-target)' ? `(request-target): ${method.toLowerCase()} ${u.pathname}${u.search}` : `${n}: ${h[n]}`)).join('\n');
  const signature = sign('sha256', Buffer.from(signing), priv).toString('base64');
  h.authorization = `Signature version="1",keyId="${keyId}",algorithm="rsa-sha256",headers="${names.join(' ')}",signature="${signature}"`;
  return h;
}
function ociCall(method, url, body, auth, extra = {}) {
  return new Promise((resolve) => {
    const headers = { ...ociSignedHeaders({ method, url, body, ...auth }), accept: 'application/json', ...extra };
    const req = httpsRequest(url, { method, headers, timeout: OCI.TIMEOUT_MS }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ } resolve({ status: res.statusCode, json, text: text.slice(0, 300) }); });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve({ status: 0, json: null, text: String(e.message || e) }));
    if (body != null) req.write(body);
    req.end();
  });
}

export async function jobOciA1() {
  const st = (await kvGet(OCI.STATE)) || {};
  if (st.instance) return { done: true, instance: st.instance, launched_at: st.launched_at };
  const k = await ociKey();
  const co = await s3Get(OCI.CONF);
  const conf = co ? JSON.parse(co.buf.toString('utf8')) : null;
  if (!conf || !conf.enabled) return { waiting: 'settings', fingerprint: k.fingerprint, public_key: k.pub };
  const auth = { keyId: `${conf.tenancy}/${conf.user}/${k.fingerprint}`, priv: k.priv };
  const base = `https://iaas.${conf.region}.oraclecloud.com/20160918`;
  // A server launched earlier (by this job or by hand) under the same name ends the search.
  const ls = await ociCall('GET', `${base}/instances?compartmentId=${encodeURIComponent(conf.compartment)}&displayName=${encodeURIComponent(conf.name)}`, null, auth);
  if (ls.status !== 200) return { error: `list instances ${ls.status}: ${(ls.json && ls.json.message) || ls.text}`, fingerprint: k.fingerprint, ...(ls.status === 401 ? { public_key: k.pub } : {}) };
  const live = (ls.json || []).find((i) => !/TERMINAT/.test(i.lifecycleState));
  if (live) { await kvPut(OCI.STATE, { ...st, instance: live.id, launched_at: live.timeCreated }); return { done: true, instance: live.id, state: live.lifecycleState }; }
  const boot = await s3Get(conf.user_data_key);
  if (!boot) return { error: 'bootstrap script missing: ' + conf.user_data_key };
  const tries = [];
  for (const ad of conf.ads) for (const sc of conf.shapes) {
    const body = JSON.stringify({
      availabilityDomain: ad, compartmentId: conf.compartment, displayName: conf.name, shape: 'VM.Standard.A1.Flex', shapeConfig: sc,
      sourceDetails: { sourceType: 'image', imageId: conf.image, bootVolumeSizeInGBs: conf.boot_gb },
      createVnicDetails: { subnetId: conf.subnet, assignPublicIp: true, hostnameLabel: conf.hostname },
      metadata: { ssh_authorized_keys: conf.ssh_public_key, user_data: boot.buf.toString('base64') },
    });
    const r = await ociCall('POST', `${base}/instances`, body, auth, { 'opc-retry-token': createHash('sha256').update(`${ad}|${JSON.stringify(sc)}|${new Date().toISOString().slice(0, 15)}`).digest('hex').slice(0, 64) });
    if (r.status === 200 && r.json && r.json.id) {
      await kvPut(OCI.STATE, { ...st, instance: r.json.id, launched_at: new Date().toISOString(), ad, shape: sc, tries: (st.tries || 0) + tries.length + 1 });
      return { launched: true, instance: r.json.id, ad, shape: sc };
    }
    tries.push({ ad: ad.replace(/^.*:/, ''), ocpus: sc.ocpus, status: r.status, message: String((r.json && r.json.message) || r.text).slice(0, 80) });
    if (r.status === 401 || r.status === 404) break;   // signature or permission: no other attempt will differ
  }
  await kvPut(OCI.STATE, { ...st, tries: (st.tries || 0) + tries.length, last_at: new Date().toISOString(), last: tries.slice(-1)[0] || null });
  return { launched: false, attempts: tries, total_tries: (st.tries || 0) + tries.length };
}
