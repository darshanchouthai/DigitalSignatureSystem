# Digital Signature System

The Digital Signature System is a secure platform for creating, verifying, and managing digital signatures using RSA encryption. The system also integrates login and registration features with face recognition for enhanced security. This project consists of the following core functionalities:

- **User Authentication (Login and Registration)**
- **Primary Key and Public Key Generation using RSA Algorithm**
- **Signature Management**: Generate Signature, Verify Signature, Co-owner Signature, and Verify Multi-Signature.

---

## Features

### 1. **User Authentication**
- **Registration**:
  - Users register with a username and face recognition.
  - Upon successful registration, a primary key and public key are generated using the RSA algorithm and stored in the database.

- **Login**:
  - Users log in using their username and face recognition for secure access.

---

### 2. **Core Functionalities**

#### a) **Generate Signature**
- Users can create a digital signature by entering:
  - **Receiver Name**
  - **Co-owner (optional)**
  - **Message**
- The system generates a digital signature using the **receiver's public key** (RSA algorithm) and displays the following details:
  - Receiver Name
  - Co-owner Name (if provided)
  - Generated Signature
- A button is provided to generate the signature.

#### b) **Verify Signature**
- Users can verify signatures assigned to them by:
  - Viewing their private key displayed in a secure box.
  - Clicking the "Decode/Unlock Message" button.
- The process:
  - Enter the **Message ID** and **Private Key**.
  - The system attempts to decrypt the message using the receiver's private key.
  - **Success**: Displays the actual message.
  - **Failure**: Displays "Decryption Failed".

#### c) **Co-Owner Signature**
- If a user is listed as a **Co-owner**:
  - They can view messages requiring their signature.
  - By clicking "Sign Message," the message is forwarded to the receiver.
  
#### d) **Verify Multi-Signature**
- Displays the user's private key in a secure box.
- Fetches messages where the user is listed as **both a receiver and a co-owner**.
- Users can decrypt messages by:
  - Entering their **Private Key**.
  - The system verifies the decryption using RSA:
    - **Success**: Displays the actual message.
    - **Failure**: Displays "Decryption Failed".

---

## Classes

### 1. `GenerateSignature`
- Handles the process of generating a digital signature using the receiver's public key.

### 2. `VerifySignature`
- Allows users to verify messages assigned to their user ID using their private key.

### 3. `CoOwnerSignature`
- Facilitates co-owners to sign messages and forward them to the receiver.

### 4. `VerifyMultiSignature`
- Enables decryption of messages that require both receiver and co-owner signatures for validation.

---

## Technologies Used

- **Backend**: Python (Flask/Django) with RSA implementation for encryption.
- **Frontend**: HTML, CSS, JavaScript for UI.
- **Database**: MySQL/PostgreSQL for storing user credentials, keys, and messages.
- **Face Recognition**: OpenCV/DeepFace for user authentication.

---

## How to Run the Project

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repository/digital-signature-system.git
   cd digital-signature-system
