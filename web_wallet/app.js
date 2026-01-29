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

const getStatus = async () => {
  const url = `${baseUrl()}/status`;
  return fetchJson(url);
};

const getAccount = async (id) => {
  const url = `${baseUrl()}/account?id=${encodeURIComponent(id)}`;
  return fetchJson(url);
};

const sendTransfer = async (from, to, amount, fee) => {
  const url = `${baseUrl()}/sendTransfer`;
  const body = JSON.stringify({ from, to, amount, fee });
  return fetchJson(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body
  });
};

el('statusOut').textContent = 'Waiting for action.';
el('balanceOut').textContent = 'Waiting for action.';
el('sendOut').textContent = 'Waiting for action.';
el('txProofOut').textContent = 'Waiting for action.';

el('btnStatus').addEventListener('click', async () => {
  try {
    const v = await getStatus();
    setOut(el('statusOut'), v, true);
  } catch (e) {
    setOut(el('statusOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnBalance').addEventListener('click', async () => {
  try {
    const id = el('accountId').value;
    const v = await getAccount(id);
    if (v === null) {
      setOut(el('balanceOut'), { id, balance: 0, note: 'missing' }, true);
      return;
    }
    if (typeof v === 'object' && v && 'balance' in v) {
      setOut(el('balanceOut'), { id: v.id ?? id, balance: v.balance, nonce: v.nonce }, true);
      return;
    }
    setOut(el('balanceOut'), v, true);
  } catch (e) {
    setOut(el('balanceOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnSend').addEventListener('click', async () => {
  try {
    const from = el('fromId').value;
    const to = el('toId').value;
    const amount = Number(el('amount').value);
    const fee = Number(el('fee').value);
    const v = await sendTransfer(from, to, amount, fee);
    setOut(el('sendOut'), v, true);
  } catch (e) {
    setOut(el('sendOut'), String(e && e.message ? e.message : e), false);
  }
});

el('btnVerifyTxProof').addEventListener('click', async () => {
  try {
    const hex = el('txProofHex').value;
    if (!window.RandProof || typeof window.RandProof.verifyTxInclusionProofHex !== 'function') {
      throw new Error('proof verifier not loaded');
    }
    const res = await window.RandProof.verifyTxInclusionProofHex(hex);
    setOut(el('txProofOut'), res, !!(res && res.ok));
  } catch (e) {
    setOut(el('txProofOut'), String(e && e.message ? e.message : e), false);
  }
});
