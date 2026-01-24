# 🍪 OREOCHAIN

> **Decentralized Document Storage using Blockchain & IPFS**

OREOCHAIN is a secure, decentralized, and tamper-proof document storage system built using **Blockchain** and **IPFS (InterPlanetary File System)**. The project ensures document authenticity and integrity by storing cryptographic hashes on the blockchain while keeping actual files distributed across IPFS.

This project is designed as a **final-year engineering project**, with real-world relevance in **secure storage, Web3, and decentralized infrastructure**.

---

## 🚀 Project Overview

Traditional centralized storage systems suffer from security risks, data tampering, and single points of failure. **OREOCHAIN** solves these challenges by combining:

* **Blockchain** → Immutable storage of document hashes
* **IPFS** → Decentralized and content-addressed file storage

This architecture guarantees:

* Data integrity
* Transparency
* Decentralization
* Trustless verification

---

## ✨ Key Features

* 🔐 **Tamper-Proof Document Storage**
  Document hashes stored on blockchain ensure immutability.

* 🌐 **Decentralized Architecture**
  No centralized server or single point of failure.

* ⚡ **Fast Retrieval & Verification**
  Retrieve documents instantly using IPFS hashes.

* 🧩 **Blockchain-Based Proof**
  Anyone can verify document authenticity.

* 🖥️ **User-Friendly Interface**
  Simple UI for uploading and retrieving documents.

* 📁 **Multi-Format Support**
  Supports PDFs, images, text files, and more.

---

## 🛠️ Tech Stack

* **Blockchain:** Ethereum
* **Smart Contracts:** Solidity
* **Decentralized Storage:** IPFS
* **Wallet Integration:** MetaMask
* **Frontend:** HTML, CSS, JavaScript
* **Blockchain Interaction:** Web3.js / Ethers.js
* **IPFS Provider:** Infura

---

## 📋 Prerequisites

Ensure you have the following installed:

* Node.js & npm
* MetaMask browser extension
* Infura account (IPFS API Key & Secret)
* Remix Online IDE
* VS Code with Live Server extension

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Rio2802/OREOCHAIN.git
cd OREOCHAIN
```

---

### 2️⃣ Install Dependencies

```bash
npm install
```

---

### 3️⃣ Deploy Smart Contract

1. Open **Remix IDE** (online)
2. Upload `contract.sol`
3. Compile and deploy the smart contract
4. Copy the deployed **contract address**

---

### 4️⃣ Configure Blockchain Settings

* Paste the **contract address** into `app.js`
* Set the **network URL** and **block explorer URL**
* Ensure MetaMask is connected to the same network

---

### 5️⃣ Configure IPFS (Infura)

1. Create an account on **Infura**
2. Generate an **IPFS API Key & Secret**
3. Paste them inside the `uploadToInfura()` function in `app.js`

---

### 6️⃣ Run the Application

* Open `index.html` using **Live Server**
* Connect MetaMask wallet
* Ensure correct network selection

---

## 📌 Usage Guide

### ➕ Add Exporter

1. Click **Add Exporter**
2. Enter the exporter’s **MetaMask wallet address**
3. Confirm the transaction

---

### 📤 Upload Document

1. Click **Upload Document**
2. Select a file from your system
3. The system will:

   * Encrypt the file
   * Upload it to IPFS
   * Store its hash on the blockchain

---

### 📥 Retrieve Document

1. Click **Retrieve Document**
2. Enter the document hash
3. The document is fetched from IPFS and displayed

---

## 🔒 Security Highlights

* Immutable blockchain records
* Content-addressed IPFS storage
* Wallet-based authentication
* No centralized database

---

## 🔮 Future Enhancements

* Role-based access control
* Multi-chain support
* File versioning
* Advanced encryption
* Improved UI/UX

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 🤝 Contributing

Contributions are welcome. Fork the repository and submit pull requests.

---

## 📬 Contact

For queries or collaboration, feel free to connect.

---

> **OREOCHAIN – Secure. Decentralized. Trustless Document Storage.**
