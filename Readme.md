BlockChain-Based Document Storing with IPFS

Overview

This project aims to create a secure and decentralized system for document storage using Blockchain and InterPlanetary File System (IPFS) technologies. The system stores the hash of documents on the Blockchain network and the documents themselves on the IPFS network. This ensures that documents cannot be tampered with or altered, while allowing easy retrieval and verification by authorized parties.

Features

Secure Document Storage: Ensures integrity and security using Blockchain and IPFS.

Decentralized Architecture: Eliminates central authority and single points of failure.

Fast and Easy Retrieval: Allows seamless document retrieval and verification.

User-Friendly Interface: Provides a simple UI for document upload and retrieval.

Support for Multiple Document Formats: Enables storing various file types.

Requirements

Node.js and npm installed on your system

MetaMask Wallet

IPFS API (key and secret), which can be obtained from Infura

Installation

Install the required packages:

npm install

Deploy the contract.sol using Remix Online IDE.

After deployment, copy the contract address from Remix.

Paste it into the app.js contract address field.

Specify the network URL and network explorer URL (available in MetaMask network settings).

Open the application in your browser using a Live Server Extension.

To store and retrieve documents, create a new Infura account at Infura, then use the provided API key and secret. Paste them in the uploadToInfura function in app.js.

Usage

Add an Exporter:

Click on the "Add Exporter" button and enter the exporter's MetaMask address.

Upload a Document:

Click on the "Upload Document" button and select a file from your computer.

The document will be encrypted and stored in the IPFS network.

Its hash will be recorded on the Blockchain.

Retrieve a Document:

Click on the "Retrieve Document" button.

Enter the document's hash.

The system will fetch the document from IPFS and display it.

License