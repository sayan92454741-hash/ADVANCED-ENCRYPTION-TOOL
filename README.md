# ADVANCED-ENCRYPTION-TOOL

"COMPANY" : CODTECH IT SOLUTIONS

"NAME" : SAYAN PANIGRAHI

"INTERN ID" : CT04DR1763

"DOMAIN" : CYBER SECURITY AND ETHICAL HACKING

"DURATION" : 4 WEEKS

"MENTOR" : NEELA SANTOSH

# DESCRIBED ABOUT THE TASK

Data security is one of the most important requirements in modern computing. Sensitive documents, personal files, and confidential information must be protected from unauthorized access, especially when stored on computers, transferred through networks, or uploaded to cloud platforms. To address this need, the Advanced AES-256 Encryption Tool was developed as a secure, user-friendly desktop application capable of encrypting and decrypting files using the AES-256 encryption standard, one of the strongest and most widely trusted cryptographic algorithms in the world.

The main objective of this project is to create a robust and easy-to-use encryption application that allows users to protect their files with a password. The tool uses AES (Advanced Encryption Standard) with a 256-bit key, which is considered military-grade encryption. AES-256 is resistant to brute-force attacks and is widely used in government, banking, and enterprise systems for secure data protection.

This application uses the Python Cryptography Library to ensure reliable and secure implementation of AES-256 in GCM (Galois/Counter Mode). AES-GCM is chosen because it provides both confidentiality and integrity, meaning it not only encrypts the data but also prevents tampering. Each encryption operation generates a unique salt, nonce, and authentication tag, making every encrypted file unique even if the same password is used multiple times.

To make key management secure, the tool uses PBKDF2-HMAC-SHA256, a strong key-derivation algorithm. Instead of using the user’s password directly as a key, PBKDF2 transforms the password into a 256-bit key through thousands of iterations. This prevents dictionary and brute-force attacks, improving the overall security of the system.

The tool includes a complete Graphical User Interface (GUI) built with Tkinter. Users can easily select an input file, choose an output location, enter a password, and pick either encryption or decryption mode. A progress bar and log window provide real-time updates so users can monitor the file processing. Encryption and decryption operations are handled in separate background threads to keep the GUI responsive.

To improve reliability, the program also includes file-lock detection, especially for environments where files may be locked by cloud-sync services like OneDrive, or opened in applications such as Word or Excel. If a file is locked or unavailable, the tool detects the issue and informs the user with a clear message instead of crashing.

# OUTPUT

Overall, this project demonstrates a practical implementation of advanced cryptography, secure key management, and user-friendly design. The result is a dependable desktop application suitable for students, professionals, and organizations who need a simple yet powerful way to protect sensitive files using strong, modern encryption techniques.
