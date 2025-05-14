# 🔐Text & file encryptor
This is a secure desktop application built with PyQt5 that allows you to encrypt and decrypt text and files using a secret phrase. The app uses robust encryption techniques to ensure the security of your data. It supports encrypting and decrypting both text and files of any extension.

### Features
- 📝 Encrypt and decrypt text with a secret phrase.
- 📁 Encrypt and decrypt files with any extension, appending `.enc` to encrypted files.
- 💻 Intuitive and clean GUI built with PyQt5.

## 📥Installation
To run the project locally, follow these steps:
  
  ```bash
  git clone https://github.com/mashisdev/text-and-file-encoder.git
  cd text-and-file-encoder
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  python main.py
  ```

## 🧪Run Tests

  ``` bash
  pip install pytest
  pytest
