# 🍪 OREOCHAIN

> **Decentralized Document Storage using Blockchain & IPFS**

OREOCHAIN is a secure, decentralized, and tamper-proof document storage system built using **Blockchain** and **IPFS (InterPlanetary File System)**. The project ensures document authenticity and integrity by storing cryptographic hashes on the blockchain while keeping the actual documents distributed across IPFS.

This project is developed as a **final-year engineering project** with real-world relevance in **Web3, decentralized storage, and secure systems**.

---

## 🚀 Project Overview

Traditional centralized document storage systems suffer from:
- Single points of failure
- Data tampering risks
- Lack of transparency
- Central authority dependency

**OREOCHAIN** solves these problems by combining:

- **Blockchain** → Immutable storage of document hashes  
- **IPFS** → Decentralized, content-addressed file storage  

This architecture guarantees:
- Data integrity
- Transparency
- Decentralization
- Trustless verification

---

## ✨ Key Features

- 🔐 **Tamper-Proof Storage**  
  Document hashes stored on blockchain ensure immutability.

- 🌐 **Decentralized Architecture**  
  No centralized server or single point of failure.

- ⚡ **Fast Retrieval & Verification**  
  Documents are retrieved using IPFS hashes.

- 🧩 **Blockchain-Based Proof**  
  Anyone can verify document authenticity.

- 🖥️ **User-Friendly Interface**  
  Simple UI for uploading and retrieving documents.

- 📁 **Multi-Format Support**  
  Supports PDFs, images, text files, and more.

---

## 🛠️ Tech Stack

- **Blockchain:** Ethereum  
- **Smart Contracts:** Solidity  
- **Decentralized Storage:** IPFS  
- **Wallet Integration:** MetaMask  
- **Frontend:** HTML, CSS, JavaScript  
- **Blockchain Interaction:** Web3.js / Ethers.js  
- **IPFS Provider:** Infura (or Pinata)

---

## 📋 Prerequisites

Make sure you have the following installed:

- Node.js & npm  
- MetaMask browser extension  
- Infura / Pinata IPFS API credentials  
- Remix Online IDE  
- VS Code with Live Server extension  

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Rio2802/OREOCHAIN.git
cd OREOCHAIN

npm install

3️⃣ Deploy Smart Contract

Open Remix IDE (online)

Upload contract.sol

Compile and deploy the smart contract

Copy the deployed contract address

4️⃣ Configure Frontend

In app.js:

Paste the deployed contract address

Configure:

Network RPC URL

Block explorer URL

Ensure MetaMask is connected to the same network

5️⃣ Configure IPFS

Inside the uploadToInfura() function in app.js, add:

IPFS API Key

IPFS API Secret
(Infura or Pinata can be used as the IPFS provider)


6️⃣ Run the Application

Right-click index.html

Open with Live Server

Connect MetaMask wallet

Select the correct blockchain network

📌 Usage Guide
➕ Add Exporter

Click Add Exporter

Enter the exporter’s MetaMask wallet address

Confirm the transaction via MetaMask

📤 Upload Document

Click Upload Document

Select any file from your system

The system will:

Upload the file to IPFS

Generate a unique IPFS hash

Store the hash on the blockchain

📥 Retrieve Document

Click Retrieve Document

Enter the document hash

The file is fetched from IPFS and displayed

🏗️ System Architecture
Frontend (HTML / JavaScript)
│
├── MetaMask Wallet Integration
├── IPFS (Infura / Pinata)
│
Smart Contract (Solidity)
└── Stores IPFS Hashes on Blockchain


🔒 Security Highlights

Immutable blockchain records

Content-addressed IPFS storage

Wallet-based authentication

No centralized database or server

🔮 Future Enhancements

Role-based access control

Multi-chain support

File versioning

Advanced encryption mechanisms

Improved UI/UX

📜 License

This project is licensed under the MIT License.

🤝 Contributing

Contributions are welcome.
Fork the repository and submit pull requests.

📬 Contact

For queries or collaboration, feel free to connect.

