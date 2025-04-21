Post-Quantum Cryptography Web Application
This is a Flask-based web application that demonstrates the use of Post-Quantum Cryptography (PQC) using the ML_KEM_512 key exchange method. It allows for the generation of public/private key pairs, encryption, and decryption of messages, all using the power of quantum-resistant cryptographic techniques.
Live Demo : https://pqc-web-app.onrender.com/
You can try out the live demo of the application at the following link:
 Live Demo
Features
Key Generation: Generate public and private key pairs for Post-Quantum Cryptography.


Encryption: Encrypt messages using the generated keys, with AES encryption for added security.


Decryption: Decrypt the messages back to their original form.


Tech Stack
Backend: Flask (Python web framework)


Post-Quantum Cryptography: ML_KEM_512 (Quantum-safe key exchange method)


Symmetric Encryption: AES encryption for message security


Frontend: Simple HTML and JavaScript for interacting with the Flask backend


Installation
To run the project locally, follow these steps:
Clone the repository:

 

git clone https://github.com/yourusername/PQC-Web-App.git


Navigate to the project directory:

 

cd PQC-Web-App


Create a virtual environment:

 

python -m venv venv


Activate the virtual environment:


For Windows:

 
.\venv\Scripts\activate


For Mac/Linux:

 

source venv/bin/activate


Install the dependencies:

 

pip install -r requirements.txt


Run the application:



python app.py
 Your Flask app should now be running at http://127.0.0.1:5000.


Usage
Generate Keys: Click on the button to generate the public and private keys.


Encrypt a Message: Enter a message to encrypt using the generated public key.


Decrypt a Message: Use the private key to decrypt the previously encrypted message.


Security
The app uses the Talisman library for adding security headers to the application and environment variables for sensitive data, such as the app's secret key.
License
This project is licensed under the MIT License - see the LICENSE file for details.

