import { HDNodeWallet, SigningKey } from "ethers";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const escapeHtml = (s) =>
  String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

function strip0x(h) {
  const s = String(h ?? "");
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

async function sha256Bits(entropyBytes) {
  const entropy = new Uint8Array(entropyBytes);
  const hash = await crypto.subtle.digest("SHA-256", entropy);
  const hashBytes = new Uint8Array(hash);
  const entBits = entropy.length * 8;
  const csLen = entBits / 32;
  const hashBin = bytesToBinary(hashBytes);
  return {
    hashHex: bytesToHex(hashBytes),
    checksumBits: hashBin.slice(0, csLen),
  };
}

function render(state) {
  const {
    entropyHex = "",
    entBits = "",
    checksumBits = "",
    mnemonic = "",
    mnemonicWords = [],
    passphrase = "",
    seedHex = "",
    path = "m/44'/60'/0'/0/0",
    xprv = "",
    xpub = "",
    privHex = "",
    pubCompressedHex = "",
    pubUncompressedHex = "",
    ethAddress = "",
  } = state;
  const hasGenerated = !!mnemonic;

  $("#app").innerHTML = `
    <div class="wrap">
      <header class="header">
        <h1>加密货币钱包密钥生成原理</h1>
        <p class="sub">助记词 · 种子 · 私钥 · 公钥 · 地址 — 可视化与交互演示</p>
      </header>

      <section class="hierarchy">
        <h2>密钥层级关系</h2>
        <div class="flow-horizontal">
          <div class="node" data-step="0"><span class="label">随机熵</span><span class="size">128/256位</span></div>
          <span class="arrow-h">→</span>
          <div class="node" data-step="1"><span class="label">助记词</span><span class="size">12/24词</span></div>
          <span class="arrow-h">→</span>
          <div class="node" data-step="2"><span class="label">种子</span><span class="size">512位</span></div>
          <span class="arrow-h">→</span>
          <div class="node" data-step="3"><span class="label">主私钥</span><span class="size">BIP32</span></div>
          <span class="arrow-h">→</span>
          <div class="node" data-step="4"><span class="label">私钥</span><span class="size">256位</span></div>
          <span class="arrow-h">→</span>
          <div class="node" data-step="5"><span class="label">公钥</span><span class="size">椭圆曲线</span></div>
          <span class="arrow-h">→</span>
          <div class="node" data-step="6"><span class="label">地址</span><span class="size">20字节</span></div>
        </div>
        <p class="hint">点击下方各步骤卡片可高亮对应节点</p>
      </section>

      <section class="action">
        <button id="genBtn" class="genBtn">生成完整密钥链（仅用于学习，请勿用于真实资产）</button>
        <p class="disclaimer">本页面仅作教学演示，生成的内容不要用于真实钱包或存储资产。</p>
      </section>

      <section class="advanced collapse">
        <details>
          <summary>高级选项：输入已有助记词 / 派生路径</summary>
          <div class="panel">
            <div class="field">
              <label>助记词</label>
              <textarea id="mnemonicInput" spellcheck="false" placeholder="12 或 24 个 BIP39 单词">${escapeHtml(mnemonic)}</textarea>
            </div>
            <div class="field">
              <label>BIP39 密码（passphrase）</label>
              <input id="passphraseInput" value="${escapeHtml(passphrase)}" placeholder="可留空" />
            </div>
            <div class="field">
              <label>派生路径（BIP44）</label>
              <input id="pathInput" value="${escapeHtml(path)}" placeholder="m/44'/60'/0'/0/0" />
            </div>
            <div class="row">
              <button id="useBtn" class="ghost">使用当前输入计算</button>
              <button id="copyMnemonicBtn" class="ghost" ${mnemonic ? "" : "disabled"}>复制助记词</button>
            </div>
            <p id="mnemonicStatus" class="small" style="margin-top:10px;color:var(--muted);"></p>
          </div>
        </details>
      </section>

      <section class="section step-card" data-step="0" id="sec-0">
        <div class="section-header">
          <span class="num">0</span>
          <h2>随机熵（Entropy）</h2>
        </div>
        <p class="desc">加密安全的随机数，通常 128 位（12 词）或 256 位（24 词），是助记词与密钥的根源。</p>
        ${hasGenerated ? `<div class="example"><strong>示例：</strong><code>0x${escapeHtml(entropyHex)}</code></div>` : ""}
        <div class="edu">
          <h3>什么是熵？</h3>
          <p>熵指「随机性」—— 一串不可预测的 0/1 比特。位数越多，可能组合越多，被猜中的概率越低。钱包通常使用加密安全伪随机数生成器（CSPRNG），如浏览器中的 <code>crypto.getRandomValues()</code> 或操作系统随机源。</p>
          <h3>为什么是 128 或 256 位？</h3>
          <p>BIP39 规定两种长度：128 位（16 字节）对应 12 个助记词，256 位（32 字节）对应 24 个助记词。128 位有 2<sup>128</sup> 种可能，暴力破解几乎不可行；256 位更安全，但日常使用 12 词通常足够。</p>
          <h3>和助记词的关系</h3>
          <p>熵不是直接变成单词的。先对熵做 SHA256 取校验和，拼在熵后面，再把（熵 + 校验和）按 11 位分组，每组得到一个 0～2047 的索引，查 BIP39 词表得到对应单词。</p>
        </div>
        ${hasGenerated ? `
        <div class="mid-steps">
          <h3>本步中间步骤（生成后可看）</h3>
          <p><strong>①</strong> 熵 — ${entBits === "128" ? "16" : "32"} 字节 = ${escapeHtml(entBits)} 位，十六进制见上方。每字节 = 8 位，共 ${entBits === "128" ? "16×8" : "32×8"} = ${escapeHtml(entBits)} 位，由加密安全随机数生成器（如 <code>crypto.getRandomValues()</code>）生成。</p>
          <p><strong>②</strong> 对这 ${entBits === "128" ? "16" : "32"} 字节做 SHA256，得到 32 字节；取结果第一个字节的高 ${checksumBits?.length || 0} 位作为校验和（<code>${escapeHtml(checksumBits || "")}</code>），拼在熵后面得到 ${escapeHtml(entBits)} + ${checksumBits?.length || 0} = ${Number(entBits) + (checksumBits?.length || 0)} 位，再按每 11 位分组得到 ${entBits === "128" ? "12" : "24"} 个 0～2047 的索引，查 BIP39 词表得到 ${entBits === "128" ? "12" : "24"} 个助记词。</p>
        </div>` : ""}
      </section>

      <section class="section step-card" data-step="1" id="sec-1">
        <div class="section-header">
          <span class="num">1</span>
          <h2>助记词（Mnemonic / BIP39）</h2>
        </div>
        <p class="desc">将熵按 BIP39 词表映射为可读的 12 或 24 个英文单词，便于备份与恢复钱包。</p>
        ${hasGenerated && mnemonicWords?.length ? `
        <div class="word-grid">
          ${mnemonicWords.map((w, i) => `<span class="word" data-i="${i + 1}">${escapeHtml(w)}</span>`).join("")}
        </div>` : ""}
        <p class="flow-text">流程：熵 → 校验和 → 拼接 → 按 11 位分组 → 词表索引 → 助记词</p>
        <div class="edu">
          <h3>SHA256 是什么？</h3>
          <p>SHA-256（Secure Hash Algorithm 256-bit）是一种加密哈希算法：输入任意长度数据，输出固定 256 位（32 字节）摘要。特点：单向（无法从摘要反推原文）、抗碰撞（极难找到不同输入产生相同摘要）、雪崩效应（输入改 1 位，输出约一半位会变）。BIP39 对熵做一次 SHA256，取结果的前若干位作为校验和（128 位熵取 4 位，256 位熵取 8 位，即熵位数 / 32）。</p>
          <h3>① 校验和（Checksum）是什么？</h3>
          <p>校验和是从熵计算出的少量附加位，用于检测抄写/输入错误。方法：对熵做 SHA256，取结果的前若干位（128 位熵取 4 位，256 位熵取 8 位）。BIP39 取 SHA256 输出的<strong>第一个字节的高 4 位</strong>（128 位熵）或前 8 位（256 位熵），拼在原始熵后面。</p>
        </div>
      </section>

      <section class="section step-card" data-step="2" id="sec-2">
        <div class="section-header">
          <span class="num">2</span>
          <h2>种子（Seed）</h2>
        </div>
        <p class="desc">助记词 + 密码（passphrase）经 PBKDF2-HMAC-SHA512 迭代 2048 次，得到 512 位（64 字节）种子，是 BIP32 主密钥的输入。</p>
        ${hasGenerated && seedHex ? `
        <div class="example"><strong>salt：</strong><code>mnemonic${passphrase ? "(+" + escapeHtml(passphrase) + ")" : ""}</code></div>
        <div class="example"><strong>种子（hex）：</strong><code class="mono wrap">${escapeHtml(seedHex.slice(0, 80))}${seedHex.length > 80 ? "…" : ""}</code></div>
        <div class="edu">
          <h3>PBKDF2 是什么？</h3>
          <p>PBKDF2（Password-Based Key Derivation Function 2）是一种密钥派生函数，通过多次哈希迭代（此处 2048 次 HMAC-SHA512）增加暴力破解难度，将助记词和盐（salt）转化为固定长度的种子。</p>
        </div>` : '<p class="muted">生成密钥链后显示。</p>'}
      </section>

      <section class="section step-card" data-step="3" id="sec-3">
        <div class="section-header">
          <span class="num">3</span>
          <h2>主私钥（Master Private Key / BIP32）</h2>
        </div>
        <p class="desc">种子经 HMAC-SHA512(\"Bitcoin seed\") 得到主密钥和链码，可派生出无限个子密钥。常用 Base58 编码的扩展私钥（xprv）和扩展公钥（xpub）表示。</p>
        ${hasGenerated && xprv ? `
        <div class="example"><strong>xprv：</strong><code class="mono wrap">${escapeHtml(xprv.slice(0, 60))}…</code></div>
        <div class="example"><strong>xpub：</strong><code class="mono wrap">${escapeHtml(xpub.slice(0, 60))}…</code></div>
        <div class="edu">
          <h3>BIP32 是什么？</h3>
          <p>BIP32 定义分层确定性钱包（HD Wallet）：从单一种子可确定性派生出多条链、多个地址，便于备份和管理。扩展密钥包含私钥/公钥和链码，可继续派生下一层。</p>
        </div>` : '<p class="muted">生成密钥链后显示。</p>'}
      </section>

      <section class="section step-card" data-step="4" id="sec-4">
        <div class="section-header">
          <span class="num">4</span>
          <h2>私钥（Private Key）</h2>
        </div>
        <p class="desc">由主密钥按 BIP44 路径派生出的 256 位（32 字节）私钥，是椭圆曲线数字签名的核心秘密。</p>
        ${hasGenerated && privHex ? `
        <div class="example"><strong>路径：</strong><code>${escapeHtml(path)}</code></div>
        <div class="example"><strong>私钥（hex）：</strong><code class="mono">${escapeHtml(privHex)}</code></div>
        <div class="edu">
          <h3>BIP44 是什么？</h3>
          <p>BIP44 定义标准路径 <code>m/44'/coin'/account'/change/address_index</code>，便于多币种、多账户统一管理。例如以太坊常用 <code>m/44'/60'/0'/0/0</code>。</p>
        </div>` : '<p class="muted">生成密钥链后显示。</p>'}
      </section>

      <section class="section step-card" data-step="5" id="sec-5">
        <div class="section-header">
          <span class="num">5</span>
          <h2>公钥（Public Key）</h2>
        </div>
        <p class="desc">由私钥经 secp256k1 椭圆曲线乘法得到，可公开分享。常用压缩格式（33 字节，0x02/0x03 开头）或非压缩格式（65 字节）。</p>
        ${hasGenerated && pubCompressedHex ? `
        <div class="example"><strong>公钥（压缩）：</strong><code class="mono wrap">${escapeHtml(pubCompressedHex)}</code></div>
        <div class="example"><strong>公钥（非压缩）：</strong><code class="mono wrap">${escapeHtml(pubUncompressedHex.slice(0, 80))}…</code></div>
        <div class="edu">
          <h3>椭圆曲线是什么？</h3>
          <p>secp256k1 是比特币、以太坊等使用的椭圆曲线。私钥是一个大整数，公钥 = 私钥 × 曲线上的基点 G。从公钥推私钥在数学上不可行（离散对数难题）。</p>
        </div>` : '<p class="muted">生成密钥链后显示。</p>'}
      </section>

      <section class="section step-card" data-step="6" id="sec-6">
        <div class="section-header">
          <span class="num">6</span>
          <h2>地址（Address）</h2>
        </div>
        <p class="desc">公钥经 Keccak-256 哈希后取后 20 字节，加 0x 前缀，得到以太坊地址（EIP-55 校验和格式）。</p>
        ${hasGenerated && ethAddress ? `
        <div class="example"><strong>ETH 地址：</strong><code class="mono">${escapeHtml(ethAddress)}</code></div>
        <div class="edu">
          <h3>地址是怎么来的？</h3>
          <p>以太坊：Keccak-256(公钥) 取后 20 字节，再转十六进制加 0x。EIP-55 对字母做大小写校验和，便于检测输入错误。</p>
        </div>` : '<p class="muted">生成密钥链后显示。</p>'}
      </section>

      <footer class="footer">
        <p>实现：ethers（BIP39/BIP32/BIP44 + secp256k1），仅本地运行，不发起网络请求。</p>
      </footer>
    </div>
  `;

  $("#genBtn").onclick = () => generateAndCompute();
  $("#useBtn").onclick = () => computeFromInputs();
  const copyBtn = $("#copyMnemonicBtn");
  if (copyBtn && mnemonic) {
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(mnemonic);
        copyBtn.textContent = "已复制";
      } catch {
        copyBtn.textContent = "复制失败";
      }
    };
  }

  $$(".step-card").forEach((el) => {
    el.addEventListener("click", () => highlightNode(el.dataset.step));
  });
  $$(".flow-horizontal .node").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      highlightNode(el.dataset.step);
    });
  });
}

function highlightNode(step) {
  $$(".flow-horizontal .node").forEach((n) => n.classList.remove("active"));
  $$(".step-card").forEach((c) => c.classList.remove("active"));
  const node = $(`.flow-horizontal .node[data-step="${step}"]`);
  const card = $(`.step-card[data-step="${step}"]`);
  if (node) node.classList.add("active");
  if (card) {
    card.classList.add("active");
    card.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

function injectStyles() {
  const style = document.createElement("style");
  style.textContent = `
    :root {
      --bg: #0d1117; --panel: #161b22; --text: #e6edf3; --muted: #8b949e;
      --brand: #58a6ff; --ok: #3fb950; --warn: #d29922; --border: rgba(255,255,255,.12);
      --mono: ui-monospace, "SF Mono", Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 24px 16px 48px; }
    .header { text-align: center; margin-bottom: 24px; }
    h1 { font-size: 22px; margin: 0 0 8px; font-weight: 600; }
    .sub { margin: 0; color: var(--muted); font-size: 14px; }
    .hierarchy { margin-bottom: 24px; }
    .hierarchy h2 { font-size: 14px; color: var(--muted); margin: 0 0 12px; font-weight: 500; }
    .flow-horizontal { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-bottom: 8px; }
    .flow-horizontal .node {
      padding: 8px 12px; border-radius: 8px; border: 1px solid var(--border);
      background: var(--panel); cursor: pointer; transition: all .2s;
    }
    .flow-horizontal .node:hover, .flow-horizontal .node.active {
      border-color: var(--brand); background: rgba(88,166,255,.15);
    }
    .flow-horizontal .node .label { display: block; font-size: 12px; font-weight: 600; }
    .flow-horizontal .node .size { font-size: 11px; color: var(--muted); }
    .arrow-h { color: var(--muted); font-size: 14px; }
    .hint { font-size: 12px; color: var(--muted); margin: 0; }
    .action { text-align: center; margin-bottom: 24px; }
    .genBtn {
      display: inline-block; padding: 14px 28px; font-size: 16px; font-weight: 600;
      background: var(--ok); color: #0d1117; border: none; border-radius: 12px;
      cursor: pointer; transition: background .2s;
    }
    .genBtn:hover { background: #56d364; }
    .disclaimer { font-size: 13px; color: var(--muted); margin: 12px 0 0; }
    .advanced { margin-bottom: 24px; }
    .advanced summary { cursor: pointer; color: var(--brand); font-size: 13px; }
    .panel { margin-top: 12px; padding: 16px; border: 1px solid var(--border); border-radius: 12px; background: var(--panel); }
    .panel .field { margin-bottom: 12px; }
    .panel .field:last-of-type { margin-bottom: 0; }
    .panel label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    .panel textarea, .panel input {
      width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border);
      background: rgba(0,0,0,.3); color: var(--text);
    }
    .panel .row { display: flex; gap: 10px; margin-top: 12px; }
    button.ghost { background: transparent; border: 1px solid var(--border); color: var(--text); padding: 8px 14px; border-radius: 8px; cursor: pointer; }
    button.ghost:hover { background: rgba(255,255,255,.06); }
    button:disabled { opacity: .5; cursor: not-allowed; }
    .section { margin-bottom: 28px; padding: 20px; border: 1px solid var(--border); border-radius: 14px; background: var(--panel); cursor: pointer; transition: border-color .2s; }
    .section:hover { border-color: rgba(88,166,255,.4); }
    .section.active { border-color: var(--brand); background: rgba(88,166,255,.08); }
    .section-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
    .section-header .num { width: 32px; height: 32px; border-radius: 8px; background: rgba(88,166,255,.2); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px; }
    .section-header h2 { margin: 0; font-size: 18px; font-weight: 600; }
    .desc { margin: 0 0 16px; font-size: 14px; color: var(--muted); }
    .example { margin: 8px 0; font-size: 13px; }
    .example code { font-family: var(--mono); font-size: 12px; padding: 2px 6px; border-radius: 4px; background: rgba(0,0,0,.3); }
    .example code.mono { display: block; padding: 10px; margin-top: 6px; word-break: break-all; }
    .word-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; margin: 12px 0; }
    .word { padding: 8px 10px; border-radius: 8px; background: rgba(0,0,0,.25); font-size: 13px; font-family: var(--mono); }
    @media (max-width: 600px) { .word-grid { grid-template-columns: repeat(4, 1fr); } }
    .flow-text { font-size: 12px; color: var(--muted); margin: 12px 0; }
    .edu { margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); }
    .edu h3 { font-size: 13px; margin: 12px 0 6px; font-weight: 600; }
    .edu h3:first-child { margin-top: 0; }
    .edu p { margin: 0 0 8px; font-size: 13px; color: var(--muted); line-height: 1.65; }
    .edu code { font-family: var(--mono); font-size: 12px; padding: 1px 4px; border-radius: 4px; background: rgba(0,0,0,.3); }
    .mid-steps { margin-top: 16px; padding: 14px; background: rgba(0,0,0,.2); border-radius: 10px; }
    .mid-steps h3 { font-size: 13px; margin: 0 0 10px; }
    .mid-steps p { margin: 0 0 10px; font-size: 13px; color: var(--muted); line-height: 1.6; }
    .mid-steps p:last-child { margin-bottom: 0; }
    .muted { color: var(--muted); font-size: 13px; margin: 0; }
    .footer { text-align: center; margin-top: 32px; font-size: 12px; color: var(--muted); }
  `;
  document.head.appendChild(style);
}

async function computeAll({ mnemonic, passphrase, path }) {
  const root = HDNodeWallet.fromPhrase(mnemonic, passphrase || "", "m");
  const seedHex = strip0x(root.mnemonic.computeSeed());
  const xprv = root.extendedKey;
  const xpub = root.neuter().extendedKey;

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
  const mnemonic = ($("#mnemonicInput")?.value || "").trim().replace(/\s+/g, " ");
  const passphrase = ($("#passphraseInput")?.value || "").toString();
  const path = ($("#pathInput")?.value || "m/44'/60'/0'/0/0").toString().trim();

  let entropyHex = "";
  let entBits = "";
  let checksumBits = "";
  let mnemonicWords = [];

  try {
    if (mnemonic) {
      const root = HDNodeWallet.fromPhrase(mnemonic, passphrase || "", "m");
      const entropy = strip0x(root.mnemonic.entropy);
      entropyHex = entropy;
      entBits = String((entropy.length / 2) * 8);
      const { checksumBits: cs } = await sha256Bits(hexToBytes(entropy));
      checksumBits = cs;
      mnemonicWords = mnemonic.trim().split(/\s+/);
    }

    if (!mnemonic) {
      render({
        entropyHex, entBits, checksumBits, mnemonic, mnemonicWords, passphrase, seedHex: "", path,
        xprv: "", xpub: "", privHex: "", pubCompressedHex: "", pubUncompressedHex: "", ethAddress: "",
      });
      return;
    }

    const derived = await computeAll({ mnemonic, passphrase, path });
    render({
      entropyHex, entBits, checksumBits, mnemonic, mnemonicWords, passphrase, path,
      ...derived,
    });
  } catch (e) {
    render({
      entropyHex, entBits, checksumBits, mnemonic, mnemonicWords, passphrase, seedHex: "", path,
      xprv: "", xpub: "", privHex: "", pubCompressedHex: "", pubUncompressedHex: "", ethAddress: "",
    });
    const status = $("#mnemonicStatus");
    if (status) status.textContent = `计算失败：${e?.message || String(e)}`;
  }
}

function boot() {
  injectStyles();
  render({
    entropyHex: "", entBits: "", checksumBits: "", mnemonic: "", mnemonicWords: [],
    passphrase: "", seedHex: "", path: "m/44'/60'/0'/0/0", xprv: "", xpub: "",
    privHex: "", pubCompressedHex: "", pubUncompressedHex: "", ethAddress: "",
  });
}

boot();
