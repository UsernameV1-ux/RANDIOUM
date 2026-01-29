const el = (id) => document.getElementById(id);

const setOut = (node, obj, ok = true) => {
  const s = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  node.textContent = s;
  node.classList.remove('ok');
  node.classList.remove('err');
  node.classList.add(ok ? 'ok' : 'err');
};

const fetchJson = async (url, init) => {
  const res = await fetch(url, init);
  const text = await res.text();
  if (!res.ok) {
    throw new Error(text || String(res.status));
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const baseUrl = () => el('rpcUrl').value.replace(/\/+$/, '');

const rpcGet = async (path) => {
  const url = `${baseUrl()}${path}`;
  return fetchJson(url);
};

const rpcPost = async (path, bodyObj) => {
  const url = `${baseUrl()}${path}`;
  const body = JSON.stringify(bodyObj ?? {});
  return fetchJson(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body
  });
};

const getStatus = async () => {
  return rpcGet('/status');
};

const sendDeployRandNft = async (from, name, symbol, baseUri) => {
  return rpcPost('/tx/sendDeploy', {
    marker: 'randnft',
    from,
    args: {
      name,
      symbol,
      base_uri: baseUri
    }
  });
};

const sendCall = async (from, to, method, args) => {
  return rpcPost('/tx/sendCall', { from, to, method, args });
};

const queryOwner = async (contract, tokenId) => {
  const c = encodeURIComponent(contract);
  const t = encodeURIComponent(String(tokenId));
  return rpcGet(`/query/randnft-owner?contract=${c}&token_id=${t}`);
};

el('statusOut').textContent = 'Waiting for action.';
el('deployOut').textContent = 'Waiting for action.';
el('mintOut').textContent = 'Waiting for action.';
el('xferOut').textContent = 'Waiting for action.';
el('ownerOut').textContent = 'Waiting for action.';

el('btnStatus').addEventListener('click', async () => {
  try {
    const v = await getStatus();
    setOut(el('statusOut'), v, true);
  } catch (e) {
    setOut(el('statusOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnDeploy').addEventListener('click', async () => {
  try {
    const from = el('deployFrom').value;
    const name = el('collectionName').value;
    const symbol = el('collectionSymbol').value;
    const baseUri = el('collectionBaseUri').value;
    const v = await sendDeployRandNft(from, name, symbol, baseUri);
    setOut(el('deployOut'), v, true);
  } catch (e) {
    setOut(el('deployOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnMint').addEventListener('click', async () => {
  try {
    const contract = el('mintContract').value;
    const from = el('mintFrom').value;
    const to = el('mintTo').value;
    const tokenId = String(el('tokenId').value);
    let metadata = null;
    try {
      metadata = JSON.parse(el('metadataJson').value);
    } catch {
      throw new Error('metadata must be valid JSON');
    }
    const v = await sendCall(from, contract, 'mint', { to, token_id: tokenId, metadata });
    setOut(el('mintOut'), v, true);
  } catch (e) {
    setOut(el('mintOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnTransfer').addEventListener('click', async () => {
  try {
    const contract = el('xferContract').value;
    const from = el('xferFrom').value;
    const to = el('xferTo').value;
    const tokenId = String(el('xferTokenId').value);
    const v = await sendCall(from, contract, 'transfer', { to, token_id: tokenId });
    setOut(el('xferOut'), v, true);
  } catch (e) {
    setOut(el('xferOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnOwner').addEventListener('click', async () => {
  try {
    const contract = el('ownerContract').value;
    const tokenId = el('ownerTokenId').value;
    const v = await queryOwner(contract, tokenId);
    setOut(el('ownerOut'), v, true);
  } catch (e) {
    setOut(el('ownerOut'), String(e && e.message ? e.message : e), false);
  }
});
