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

const sendDeployRand20 = async (from, symbol, decimals, initialSupply, note) => {
  return rpcPost('/tx/sendDeploy', {
    marker: 'rand20',
    from,
    args: {
      symbol,
      decimals,
      initial_supply: initialSupply,
      note
    }
  });
};

const sendCall = async (from, to, method, args) => {
  return rpcPost('/tx/sendCall', { from, to, method, args });
};

const querySupply = async (contract) => {
  const q = encodeURIComponent(contract);
  return rpcGet(`/query/rand20-supply?contract=${q}`);
};

el('statusOut').textContent = 'Waiting for action.';
el('deployOut').textContent = 'Waiting for action.';
el('mintOut').textContent = 'Waiting for action.';
el('xferOut').textContent = 'Waiting for action.';
el('supplyOut').textContent = 'Waiting for action.';

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
    const symbol = el('tokenSymbol').value;
    const decimals = Number(el('tokenDecimals').value);
    const initialSupply = String(el('tokenInitSupply').value);
    const note = el('deployNote').value;
    const v = await sendDeployRand20(from, symbol, decimals, initialSupply, note);
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
    const amount = String(el('mintAmount').value);
    const v = await sendCall(from, contract, 'mint', { to, amount });
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
    const amount = String(el('xferAmount').value);
    const v = await sendCall(from, contract, 'transfer', { to, amount });
    setOut(el('xferOut'), v, true);
  } catch (e) {
    setOut(el('xferOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnSupply').addEventListener('click', async () => {
  try {
    const contract = el('supplyContract').value;
    const v = await querySupply(contract);
    setOut(el('supplyOut'), v, true);
  } catch (e) {
    setOut(el('supplyOut'), String(e && e.message ? e.message : e), false);
  }
});
