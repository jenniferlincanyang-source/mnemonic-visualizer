# 助记词生成逻辑可视化（本地网页）

这是一个**纯前端**可视化小站，用于学习展示：

- BIP39：Entropy（熵）→ Checksum（校验和位）→ 助记词（Mnemonic）
- Seed：PBKDF2-HMAC-SHA512（2048 次）
- BIP32：Master xprv / xpub
- BIP44：派生路径 → 私钥 / 公钥（secp256k1）→（示例）以太坊地址

> 安全提示：仅用于学习演示。请不要把有资产的钱包助记词输入任何网页。

## 运行

```bash
npm install
npm run dev
```

启动后打开终端提示的本地地址即可。

## 部署到 GitHub Pages

推送到 `main` 分支后，会自动通过 GitHub Actions 构建并发布到 Pages。

发布链接形如：`https://<你的GitHub用户名>.github.io/<仓库名>/`

## 默认派生路径

- 以太坊：`m/44'/60'/0'/0/0`


从你这边的输出可以确认：
提交成功：[main 4baade0] Fix: random mnemonic each click...，1 个文件改动已提交
推送成功：b5b9d5d..4baade0 main -> main，远程 main 已更新
GitHub 会自动用这次提交重新构建并部署到 Pages，一般 1～2 分钟内生效。过一会儿刷新这个地址就能看到“每次点击随机生成助记词并更新整条密钥链”的版本：
https://jenniferlincanyang-source.github.io/mnemonic-visualizer/
