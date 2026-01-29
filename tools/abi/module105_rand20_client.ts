export type Address = string;

export class Rand20Client {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async rpcPost(path: string, bodyObj: unknown): Promise<any> {
    const url = `${this.baseUrl}${path}`;
    const body = JSON.stringify(bodyObj ?? {});
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(text || String(res.status));
    }
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  async mint(from: Address, contract: Address, to: string, amount: string): Promise<any> {
    return this.rpcPost('/tx/sendCall', {
      from,
      to: contract,
      method: 'mint',
      args: {
        to,
        amount
      }
    });
  }

  async transfer(from: Address, contract: Address, to: string, amount: string): Promise<any> {
    return this.rpcPost('/tx/sendCall', {
      from,
      to: contract,
      method: 'transfer',
      args: {
        to,
        amount
      }
    });
  }

  async approve(from: Address, contract: Address, spender: string, amount: string): Promise<any> {
    return this.rpcPost('/tx/sendCall', {
      from,
      to: contract,
      method: 'approve',
      args: {
        spender,
        amount
      }
    });
  }
}
