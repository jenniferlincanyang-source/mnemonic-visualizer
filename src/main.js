import { HDNodeWallet, SigningKey } from "ethers";

const $ = (sel) => document.querySelector(sel);
const escapeHtml = (s) =>
  String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

function strip0x(h) {
  const s = String(h || "");
  return s.startsWith("0x") ? s.slice(2) : s;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hexStr) {
  const h = strip0x(hexStr).toLowerCase();
  if (!h) return new Uint8Array();
  if (!/^[0-9a-f]+$/.test(h) || h.length % 2 !== 0) throw new Error("hex 格式错误");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBinary(bytes) {
  return Array.from(bytes, (x) => x.toString(2).padStart(8, "0")).join("");
}

function sha256Bits(entropyBytes) {
  // Returns { hashHex, checksumBits } where checksumBits length is ENT/32.
  const entropy = new Uint8Array(entropyBytes);
  return crypto.subtle.digest("SHA-256", entropy).then((hash) => {
    const hashBytes = new Uint8Array(hash);
    const entBits = entropy.length * 8;
    const csLen = entBits / 32;
    const hashBin = bytesToBinary(hashBytes);
    return {
      hashHex: bytesToHex(hashBytes),
      checksumBits: hashBin.slice(0, csLen),
    };
  });
}

function render({ entropyHex, entBits, checksumBits, mnemonic, passphrase, seedHex, path, xprv, xpub, privHex, pubCompressedHex, pubUncompressedHex, ethAddress }) {
  const warning =
    "安全提示：此页面仅用于学习与演示。生成/粘贴真实助记词会有泄露风险；请不要把有资产的钱包助记词输入到任何网页。";

  $("#app").innerHTML = `
    <div class="wrap">
      <header class="header">
        <div>
          <h1>助记词生成逻辑可视化</h1>
          <p class="sub">BIP39 助记词 → Seed（PBKDF2-HMAC-SHA512）→ BIP32 → BIP44 路径 → 私钥/公钥（secp256k1）</p>
        </div>
        <div class="pill">默认示例路径：<code>${escapeHtml(path)}</code>（以太坊）</div>
      </header>

      <section class="notice">
        <strong>⚠️ ${escapeHtml(warning)}</strong>
        <div class="small">所有计算均在本地浏览器完成；本页面不发起网络请求。</div>
      </section>

      <section class="panel">
        <h2>输入 / 生成</h2>
        <div class="grid2">
          <div class="field">
            <label>助记词（空则随机生成 12 词）</label>
            <textarea id="mnemonicInput" spellcheck="false" placeholder="例如：abandon abandon abandon ...">${escapeHtml(mnemonic || "")}</textarea>
            <div class="row">
              <button id="genBtn">随机生成</button>
              <button class="ghost" id="useBtn">使用当前输入计算</button>
              <button class="ghost" id="copyMnemonicBtn" ${mnemonic ? "" : "disabled"}>复制助记词</button>
            </div>
            <div id="mnemonicStatus" class="small"></div>
          </div>
          <div class="field">
            <label>可选密码（BIP39 passphrase）</label>
            <input id="passphraseInput" value="${escapeHtml(passphrase || "")}" placeholder="（可留空）" />
            <label style="margin-top:12px;">派生路径（BIP44）</label>
            <input id="pathInput" value="${escapeHtml(path)}" spellcheck="false" />
            <div class="small">常见：ETH <code>m/44'/60'/0'/0/0</code>，BTC(legacy) <code>m/44'/0'/0'/0/0</code></div>
          </div>
        </div>
      </section>

      <section class="flow">
        <h2>可视化流程（逐步展开）</h2>
        <div class="steps">
          <div class="step">
            <div class="badge">1</div>
            <div class="content">
              <div class="title">Entropy（熵）</div>
              <div class="kv"><span>位数</span><code>${escapeHtml(String(entBits || ""))}</code></div>
              <div class="kv"><span>熵（hex）</span><code class="mono">${escapeHtml(entropyHex || "")}</code></div>
            </div>
          </div>

          <div class="arrow">↓</div>

          <div class="step">
            <div class="badge">2</div>
            <div class="content">
              <div class="title">Checksum（校验和位）</div>
              <div class="kv"><span>长度</span><code>${escapeHtml(checksumBits ? checksumBits.length + " bits" : "")}</code></div>
              <div class="kv"><span>校验和</span><code class="mono">${escapeHtml(checksumBits || "")}</code></div>
              <div class="small">规则：校验和长度 = ENT / 32；取 SHA-256(entropy) 的前 CS 位。</div>
            </div>
          </div>

          <div class="arrow">↓</div>

          <div class="step">
            <div class="badge">3</div>
            <div class="content">
              <div class="title">Mnemonic（助记词，BIP39）</div>
              <div class="kv"><span>词数</span><code>${escapeHtml(mnemonic ? mnemonic.trim().split(/\\s+/).length : "")}</code></div>
              <div class="kv"><span>助记词</span><code class="mono wrapcode">${escapeHtml(mnemonic || "")}</code></div>
              <div class="small">规则：把 ENT+CS 拼接后按 11 位切分，每段映射到词表索引。</div>
            </div>
          </div>

          <div class="arrow">↓</div>

          <div class="step">
            <div class="badge">4</div>
            <div class="content">
              <div class="title">Seed（PBKDF2-HMAC-SHA512, 2048 次）</div>
              <div class="kv"><span>salt</span><code>${escapeHtml("mnemonic" + (passphrase ? "(+" + passphrase + ")" : ""))}</code></div>
              <div class="kv"><span>seed（hex）</span><code class="mono">${escapeHtml(seedHex || "")}</code></div>
            </div>
          </div>

          <div class="arrow">↓</div>

          <div class="step">
            <div class="badge">5</div>
            <div class="content">
              <div class="title">BIP32 Master（主扩展密钥）</div>
              <div class="kv"><span>xprv</span><code class="mono wrapcode">${escapeHtml(xprv || "")}</code></div>
              <div class="kv"><span>xpub</span><code class="mono wrapcode">${escapeHtml(xpub || "")}</code></div>
              <div class="small">由 seed 通过 HMAC-SHA512("Bitcoin seed") 得到 master key + chain code。</div>
            </div>
          </div>

          <div class="arrow">↓</div>

          <div class="step">
            <div class="badge">6</div>
            <div class="content">
              <div class="title">派生路径（BIP44）</div>
              <div class="kv"><span>path</span><code>${escapeHtml(path)}</code></div>
              <div class="kv"><span>私钥（hex）</span><code class="mono">${escapeHtml(privHex || "")}</code></div>
              <div class="kv"><span>公钥（compressed）</span><code class="mono wrapcode">${escapeHtml(pubCompressedHex || "")}</code></div>
              <div class="kv"><span>公钥（uncompressed）</span><code class="mono wrapcode">${escapeHtml(pubUncompressedHex || "")}</code></div>
              <div class="kv"><span>ETH 地址</span><code class="mono">${escapeHtml(ethAddress || "")}</code></div>
            </div>
          </div>
        </div>
      </section>

      <footer class="footer">
        <div class="small">实现：ethers（BIP39/BIP32/BIP44 + secp256k1；仅本地运行）。</div>
      </footer>
    </div>
  `;

  $("#genBtn").onclick = () => generateAndCompute();
  $("#useBtn").onclick = () => computeFromInputs();
  $("#copyMnemonicBtn")?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(mnemonic || "");
      $("#mnemonicStatus").textContent = "已复制助记词到剪贴板（请注意安全）。";
    } catch {
      $("#mnemonicStatus").textContent = "复制失败：浏览器可能禁止剪贴板访问。";
    }
  });
}

function injectStyles() {
  const style = document.createElement("style");
  style.textContent = `
    :root{
      --bg:#0b1020; --panel:#111a33; --panel2:#0f1730; --text:#e8eeff; --muted:#9fb0da;
      --brand:#7aa2ff; --ok:#4ade80; --warn:#fbbf24; --border:rgba(255,255,255,.08);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
    }
    *{ box-sizing:border-box; }
    body{ margin:0; font-family:var(--sans); background:radial-gradient(1200px 600px at 20% 0%, rgba(122,162,255,.25), transparent 60%), var(--bg); color:var(--text); }
    .wrap{ max-width:1100px; margin:0 auto; padding:28px 18px 60px; }
    .header{ display:flex; gap:14px; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; }
    h1{ font-size:26px; margin:0 0 6px; letter-spacing:.2px; }
    .sub{ margin:0; color:var(--muted); font-size:13px; line-height:1.5; }
    .pill{ background:rgba(122,162,255,.12); border:1px solid rgba(122,162,255,.25); padding:10px 12px; border-radius:999px; font-size:12px; color:var(--text); }
    .notice{ margin:16px 0 18px; padding:14px 14px; border:1px solid rgba(251,191,36,.35); background:rgba(251,191,36,.08); border-radius:12px; }
    .small{ font-size:12px; color:var(--muted); margin-top:6px; }
    .panel{ border:1px solid var(--border); background:linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02)); border-radius:14px; padding:16px; }
    .panel h2{ margin:0 0 12px; font-size:16px; }
    .grid2{ display:grid; grid-template-columns: 1.2fr .8fr; gap:14px; }
    @media (max-width: 920px){ .grid2{ grid-template-columns:1fr; } }
    .field label{ display:block; font-size:12px; color:var(--muted); margin-bottom:8px; }
    textarea, input{
      width:100%; border-radius:12px; border:1px solid var(--border);
      background:rgba(0,0,0,.25); color:var(--text); padding:12px 12px;
      outline:none;
    }
    textarea{ min-height:92px; resize:vertical; font-family:var(--sans); }
    input{ font-family:var(--sans); }
    textarea:focus, input:focus{ border-color: rgba(122,162,255,.6); box-shadow: 0 0 0 3px rgba(122,162,255,.15); }
    .row{ display:flex; gap:10px; margin-top:10px; flex-wrap:wrap; }
    button{
      border:1px solid rgba(122,162,255,.35);
      background:rgba(122,162,255,.18);
      color:var(--text);
      padding:10px 12px;
      border-radius:12px;
      cursor:pointer;
      font-weight:600;
    }
    button:hover{ background:rgba(122,162,255,.24); }
    button.ghost{ background:transparent; }
    button:disabled{ opacity:.45; cursor:not-allowed; }
    .flow{ margin-top:18px; }
    .flow h2{ font-size:16px; margin:0 0 10px; }
    .steps{ display:flex; flex-direction:column; gap:10px; }
    .step{ display:flex; gap:12px; padding:14px; border-radius:14px; border:1px solid var(--border); background:rgba(255,255,255,.03); }
    .badge{
      width:34px; height:34px; border-radius:10px; display:flex; align-items:center; justify-content:center;
      background:rgba(122,162,255,.16); border:1px solid rgba(122,162,255,.26); font-weight:800;
    }
    .content{ flex:1; min-width:0; }
    .title{ font-weight:800; margin-bottom:8px; }
    .kv{ display:grid; grid-template-columns: 140px 1fr; gap:10px; align-items:start; margin:6px 0; }
    .kv span{ color:var(--muted); font-size:12px; padding-top:2px; }
    code{ font-family:var(--mono); font-size:12px; }
    code.mono{ display:block; padding:10px 10px; border:1px solid var(--border); background:rgba(0,0,0,.22); border-radius:12px; overflow:auto; }
    code.wrapcode{ white-space:pre-wrap; word-break:break-word; }
    .arrow{ text-align:center; color:rgba(122,162,255,.75); font-size:18px; line-height:1; }
    .footer{ margin-top:16px; text-align:center; }
  `;
  document.head.appendChild(style);
}

async function computeAll({ mnemonic, passphrase, path }) {
  // Root ("m") for master xprv/xpub
  const root = HDNodeWallet.fromPhrase(mnemonic, passphrase || "", "m");
  const seedHex = strip0x(root.mnemonic.computeSeed());
  const xprv = root.extendedKey;
  const xpub = root.neuter().extendedKey;

  // Target path (example default is Ethereum)
  const wallet = HDNodeWallet.fromPhrase(mnemonic, passphrase || "", path);

  const privHex = strip0x(wallet.privateKey);
  const pubCompressedHex = strip0x(wallet.publicKey);
  const pubUncompressedHex = strip0x(SigningKey.computePublicKey(wallet.privateKey, false));
  const ethAddress = wallet.address;

  return { seedHex, xprv, xpub, privHex, pubCompressedHex, pubUncompressedHex, ethAddress };
}

async function generateAndCompute() {
  const wallet = HDNodeWallet.createRandom();
  $("#mnemonicInput").value = wallet.mnemonic.phrase;
  await computeFromInputs();
}

async function computeFromInputs() {
  const mnemonic = ($("#mnemonicInput").value || "").trim().replace(/\s+/g, " ");
  const passphrase = ($("#passphraseInput").value || "").toString();
  const path = ($("#pathInput").value || "m/44'/60'/0'/0/0").toString().trim();

  let entropyHex = "";
  let entBits = "";
  let checksumBits = "";

  try {
    if (mnemonic) {
      const root = HDNodeWallet.fromPhrase(mnemonic, passphrase || "", "m");
      const entropy = strip0x(root.mnemonic.entropy);
      entropyHex = entropy;
      entBits = String((entropy.length / 2) * 8);
      const { checksumBits: cs } = await sha256Bits(hexToBytes(entropy));
      checksumBits = cs;
      $("#mnemonicStatus").textContent = "助记词校验通过。";
    } else {
      $("#mnemonicStatus").textContent = "请输入助记词，或点击“随机生成”。";
    }

    if (!mnemonic) {
      render({ entropyHex, entBits, checksumBits, mnemonic, passphrase, seedHex: "", path, xprv: "", xpub: "", privHex: "", pubCompressedHex: "", pubUncompressedHex: "", ethAddress: "" });
      wireAfterRender();
      return;
    }

    const derived = await computeAll({ mnemonic, passphrase, path });

    render({
      entropyHex,
      entBits,
      checksumBits,
      mnemonic,
      passphrase,
      path,
      ...derived,
    });
    wireAfterRender();
  } catch (e) {
    render({ entropyHex, entBits, checksumBits, mnemonic, passphrase, seedHex: "", path, xprv: "", xpub: "", privHex: "", pubCompressedHex: "", pubUncompressedHex: "", ethAddress: "" });
    wireAfterRender();
    $("#mnemonicStatus").textContent = `计算失败：${e?.message || String(e)}`;
  }
}

function wireAfterRender() {
  // After re-render, re-wire status for validity on edit.
  const input = $("#mnemonicInput");
  if (!input) return;
  input.addEventListener("input", () => {
    const m = input.value.trim().replace(/\s+/g, " ");
    if (!m) {
      $("#mnemonicStatus").textContent = "";
      return;
    }
    try {
      HDNodeWallet.fromPhrase(m, ($("#passphraseInput")?.value || "").toString(), "m");
      $("#mnemonicStatus").textContent = "助记词校验通过（未重新计算）。";
    } catch {
      $("#mnemonicStatus").textContent = "助记词校验失败（未重新计算）。";
    }
  });
}

function boot() {
  injectStyles();
  render({
    entropyHex: "",
    entBits: "",
    checksumBits: "",
    mnemonic: "",
    passphrase: "",
    seedHex: "",
    path: "m/44'/60'/0'/0/0",
    xprv: "",
    xpub: "",
    privHex: "",
    pubCompressedHex: "",
    pubUncompressedHex: "",
    ethAddress: "",
  });
  wireAfterRender();
}

boot();

