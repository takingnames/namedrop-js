let prefix = "namedrop";
let apiUri = 'https://takingnames.io/namedrop';

class Client {
  constructor(token, domain, host) {
    this._token = token;
    this._domain = domain;
    this._host = host;
  }

  get domain() {
    return this._domain;
  }

  get host() {
    return this._host;
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

    const recsCopy = JSON.parse(JSON.stringify(records));

    for (const record of recsCopy) {
      if (record.domain === undefined) {
        record.domain = domain ? domain : this.domain;
      }
      if (record.host === undefined) {
        record.host = host ? host : this.host;
      }
    }

    const uri = `${apiUri}/${endpoint}`;
    const res = await fetch(uri, {
      method: 'POST',
      headers:{
        // Using text/plain is a hack to avoid CORS preflights, which are an
        // abomination
        'Content-Type': 'text/plain'
      },    
      body: JSON.stringify({
        domain: this.domain,
        token: this._token,
        records: recsCopy,
      }),
    });

    const result = await res.json();

    if (result.type !== 'success') {
      throw new Error(JSON.stringify(result, null, 2));
    }

    return result;
  }
}

function setApiUri(newUri) {
  apiUri = newUri;
}

const validPerms = [ 'servers', 'mail', 'acme' ];

function buildScope(req) {

  for (const perm of req.scopes) {
    if (!validPerms.includes(perm)) {
      throw new Error(`Invalid perm: "${perm}"`);
    }
  }

  return req.scopes.join(' ');
}

async function startAuthFlow(req) {

  const clientId = window.location.origin;
  const redirectUri = window.location.href;

  const codeVerifier = genRandomText(32);
  const codeChallenge = await generateCodeChallengeFromVerifier(codeVerifier);

  const scope = buildScope(req);

  const state = genRandomText(32);
  const authUri = `${apiUri}/authorize?client_id=${clientId}&scope=${scope}&redirect_uri=${redirectUri}&state=${state}&response_type=code&code_challenge=${codeChallenge}`;

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

  console.log(json);

  window.history.replaceState(null, '', window.location.pathname);

  return new Client(json.access_token, json.permissions[0].domain, json.permissions[0].host);
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

export default {
  setApiUri,
  checkAuthFlow,
  startAuthFlow,
  Client,
};
