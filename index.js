let prefix = "namedrop";
let DEFAULT_API_URI = 'https://takingnames.io/namedrop';

const SCOPE_HOSTS = 'namedrop-hosts';
const SCOPE_MAIL = 'namedrop-mail';
const SCOPE_ACME = 'namedrop-acme';
const SCOPE_ATPROTO_HANDLE = 'namedrop-atproto-handle';

const validScopes = [ SCOPE_HOSTS, SCOPE_MAIL, SCOPE_ACME, SCOPE_ATPROTO_HANDLE ];

class Client {
  constructor({ token, permissions, domain, host }) {
    this._token = token;
    this._domain = domain;
    this._host = host;
    this._permissions = permissions;
  }

  get domain() {
    return this._domain;
  }

  get host() {
    return this._host;
  }

  get token() {
    return this._token;
  }

  get permissions() {
    return this._permissions;
  }

  async getRecords(opt) {
    const result = await this.doRecords('get-records', opt || { records: [] });
    return result.records;
  }

  async createRecords(opt) {
    return this.doRecords('create-records', opt);
  }

  async setRecords(opt) {
    return this.doRecords('set-records', opt);
  }

  async deleteRecords(opt) {
    return this.doRecords('delete-records', opt);
  }

  async doRecords(endpoint, { domain, host, records }) {
    return doRecords(apiUri, endpoint, { token: this._token, domain, host, records });
  }
}

async function getRecords(apiUri, opt) {
  const result = await this.doRecords(apiUri, 'get-records', opt || { records: [] });
  return result.records;
}

async function createRecords(apiUri, opt) {
  return doRecords(apiUri, 'create-records', opt);
}

async function setRecords({ apiUri, request }) {
  return doRecords(apiUri, 'set-records', request);
}

async function deleteRecords(apiUri, opt) {
  return doRecords(apiUri, 'delete-records', opt);
}

async function doRecords(apiUriIn, endpoint, { token, domain, host, records }) {

  const apiUri = apiUriIn ? apiUriIn : DEFAULT_API_URI;

  const recsCopy = JSON.parse(JSON.stringify(records));

  const uri = `${apiUri}/${endpoint}`;
  const res = await fetch(uri, {
    method: 'POST',
    headers:{
      // Using text/plain is a hack to avoid CORS preflights, which are an
      // abomination
      'Content-Type': 'text/plain'
    },    
    body: JSON.stringify({
      domain,
      host,
      token,
      records: recsCopy,
    }),
  });

  const result = await res.json();

  if (result.type !== 'success') {
    throw new Error(JSON.stringify(result, null, 2));
  }

  return result;
}

function setApiUri(newUri) {
  apiUri = newUri;
}

function buildScope(req) {

  for (const scope of req.scopes) {
    if (!validScopes.includes(scope)) {
      throw new Error(`Invalid scope: "${scope}"`);
    }
  }

  return req.scopes.join(' ');
}

async function startAuthCodeFlow({ apiUri, authRequest }) {

  const authReq = authRequest;

  if (!authReq.redirectUri) {
    throw new Error("Missing redirectUri");
  }

  const clientId = authReq.client_id || authReq.redirectUri;

  const codeVerifier = genRandomText(32);
  const codeChallenge = await generateCodeChallengeFromVerifier(codeVerifier);

  const state = genRandomText(32);

  const scopeParam = authReq.scopes.join(' ');

  const params = new URLSearchParams();
  params.set('client_id', clientId);
  params.set('redirect_uri', authReq.redirectUri);
  params.set('scope', scopeParam);
  params.set('state', state);
  params.set('response_type', 'code');
  params.set('code_challenge', codeChallenge);
  params.set('code_challenge_method', 'S256');

  const auri = apiUri ? apiUri : DEFAULT_API_URI;

  const flowState = {
    state,
    authUri: `${auri}/authorize?${params.toString()}`,
    apiUri: auri,
    clientId,
    redirectUri: authReq.redirectUri,
    codeVerifier,
  };

  return flowState;
}

async function completeAuthCodeFlow({ flowState, code }) { 

  const res = await fetch(flowState.apiUri + "/token", {
    method: 'POST',
    headers:{
      'Content-Type': 'application/x-www-form-urlencoded'
    },    
    body: new URLSearchParams({
      code,
      client_id: flowState.clientId,
      redirect_uri: flowState.redirectUri,
      code_verifier: flowState.codeVerifier,
      grant_type: 'authorization_code',
    }),
  });

  if (!res.ok) {
    throw new Error(res.text());
  }

  return res.json();
}

async function startAuthFlow(req) {

  const clientId = window.location.origin;
  const redirectUri = window.location.href;

  const codeVerifier = genRandomText(32);
  const codeChallenge = await generateCodeChallengeFromVerifier(codeVerifier);

  const scope = buildScope(req);

  const state = genRandomText(32);
  const authUri = `${apiUri}/authorize?client_id=${clientId}&scope=${scope}&redirect_uri=${redirectUri}&state=${state}&response_type=code&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  const authRequest = {
    apiUri,
    clientId,
    redirectUri,
    codeVerifier,
  };

  localStorage.setItem(state, JSON.stringify(authRequest));
  window.location.href = authUri;
}

async function checkAuthFlow() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');

  if (!code || !state) {
    return;
  }

  window.history.replaceState(null, '', window.location.pathname);

  const authRequestJson = localStorage.getItem(state);
  localStorage.removeItem(state);

  if (!authRequestJson) {
    throw new Error("No such auth request");
  }

  const authRequest = JSON.parse(authRequestJson);

  const res = await fetch(authRequest.apiUri + "/token", {
    method: 'POST',
    headers:{
      'Content-Type': 'application/x-www-form-urlencoded'
    },    
    body: new URLSearchParams({
      code,
      client_id: authRequest.clientId,
      redirect_uri: authRequest.redirectUri,
      grant_type: 'authorization_code',
      code_verifier: authRequest.codeVerifier,
    }),
  });

  const json = await res.json();

  return new Client({
    token: json.access_token,
    permissions: json.permissions,
    domain: json.permissions[0].domain,
    host: json.permissions[0].host,
  });
}

function genRandomText(len) {
  const possible = "0123456789abcdefghijkmnpqrstuvwxyz";

  let text = "";
  for (let i = 0; i < len; i++) {
    const randIndex = Math.floor(Math.random() * possible.length);
    text += possible[randIndex];
  }

  return text;
}

// Taken from https://stackoverflow.com/a/63336562/943814
function sha256(plain) {
  // returns promise ArrayBuffer
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest("SHA-256", data);
}
function base64urlencode(a) {
  var str = "";
  var bytes = new Uint8Array(a);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
async function generateCodeChallengeFromVerifier(v) {
  var hashed = await sha256(v);
  var base64encoded = base64urlencode(hashed);
  return base64encoded;
}

export {
  SCOPE_HOSTS,
  SCOPE_MAIL,
  SCOPE_ACME,
  SCOPE_ATPROTO_HANDLE,
  setApiUri,
  checkAuthFlow,
  startAuthFlow,
  Client,
  startAuthCodeFlow,
  completeAuthCodeFlow,
  setRecords,
};
