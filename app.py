from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import mysql.connector
import base64
import cv2
import numpy as np
import face_recognition
import os
import rsa
from werkzeug.utils import secure_filename
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

app = Flask(__name__)
app.secret_key = '41f4cfa3623d79af0b306d17f321d482'  # Secure key for session management

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'database': 'Digisignature',
    'user': 'root',
    'password': 'Darshan@2003'
}

def get_db_connection():
    """Establish a connection to the MySQL database."""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        return None

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        # Render the registration page
        return render_template("register.html")

    # Handle POST request (form submission)
    user_id = request.form['userId']
    face_image_base64 = request.form['faceImage']

    # Decode Base64 image
    try:
        face_image_data = base64.b64decode(face_image_base64.split(",")[1])
    except Exception as e:
        return render_template("register.html", error="Invalid face image!")

    try:
        # Connect to MySQL database
        connection = get_db_connection()
        if not connection:
            return "Database connection failed!"

        cursor = connection.cursor()

        # Check if the user ID already exists
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        if cursor.fetchone():
            return render_template("register.html", error="User ID already exists!")

        # Generate RSA private and public keys
        public_key, private_key = rsa.newkeys(2048)

        # Convert keys to PEM format for storage
        private_key_pem = private_key.save_pkcs1(format='PEM')
        public_key_pem = public_key.save_pkcs1(format='PEM')

        # Insert user ID, face image, and keys into the database
        query = """
        INSERT INTO users (user_id, face_image, private_key, public_key) 
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, face_image_data, private_key_pem, public_key_pem))
        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for('login'))
    except Exception as e:
        print(f"Error during registration: {e}")
        return render_template("register.html", error="An error occurred during registration. Please try again.")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Render the login.html page
        return render_template("login.html", error=None)
    
    user_id = request.form['userId']
    login_image_base64 = request.form['faceImage']

    # Decode Base64 image
    login_image_data = base64.b64decode(login_image_base64.split(",")[1])

    try:
        # Connect to MySQL database
        connection = get_db_connection()
        if not connection:
            return render_template("login.html", error="Database connection failed!")

        cursor = connection.cursor()

        # Fetch stored face image for the given user ID
        query = "SELECT face_image FROM users WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()

        if not result:
            # User ID not found
            return render_template("login.html", error="Invalid details!")

        # Compare faces using face_recognition
        stored_face_image = np.frombuffer(result[0], np.uint8)
        stored_face_image = cv2.imdecode(stored_face_image, cv2.IMREAD_COLOR)

        login_face_image = np.frombuffer(login_image_data, np.uint8)
        login_face_image = cv2.imdecode(login_face_image, cv2.IMREAD_COLOR)

        if compare_faces(stored_face_image, login_face_image):
            session['user_id'] = user_id  # Store user session
            return redirect(url_for('generate_signature'))
        else:
            # Face mismatch
            return render_template("login.html", error="Invalid details!")
    except Exception as e:
        return render_template("login.html", error="An error occurred. Please try again.")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"Welcome, {session['user_id']}! You have successfully logged in."


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return render_template("login.html")


def compare_faces(stored_image, login_image):
    """
    Compare two face images for similarity using face_recognition.
    Return True if faces match, else False.
    """
    try:
        # Encode the stored and login face images
        stored_encoding = face_recognition.face_encodings(stored_image)
        login_encoding = face_recognition.face_encodings(login_image)

        # Ensure that both images have detectable faces
        if len(stored_encoding) == 0 or len(login_encoding) == 0:
            print("No face detected in one of the images.")
            return False

        # Compare faces
        match_results = face_recognition.compare_faces([stored_encoding[0]], login_encoding[0], tolerance=0.6)
        return match_results[0]
    except Exception as e:
        print(f"Error in face comparison: {e}")
        return False

from datetime import datetime, timedelta

@app.route('/generate_signature', methods=['GET', 'POST'])
def generate_signature():
    if request.method == 'GET':
        return render_template('dashboard.html')

    try:
        # Extract and log incoming data
        data = request.json
        print("Received Payload:", data)

        if not data:
            return jsonify({"error": "No data provided"}), 400

        receiver_name = data.get('receiverName')
        co_owner_name = data.get('coOwnerName')  # Optional co-owner
        message = data.get('messageText')

        # Validate required fields
        print(f"Receiver Name: {receiver_name}, Message Text: {message}, Co-Owner Name: {co_owner_name}")
        if not receiver_name or not message:
            return jsonify({"error": "Missing 'receiverName' or 'messageText'"}), 400

        # Ensure the user is logged in
        if 'user_id' not in session:
            return jsonify({"error": "User not logged in"}), 401

        # Establish database connection
        connection = get_db_connection()
        if not connection:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = connection.cursor(dictionary=True)
        sender_id = session['user_id']

        # Fetch receiver details
        cursor.execute('SELECT id, user_id, public_key FROM users WHERE user_id = %s', (receiver_name,))
        receiver = cursor.fetchone()
        if not receiver:
            return jsonify({"error": "Invalid receiver"}), 400

        receiver_public_key_pem = receiver['public_key']

        # Ensure the public key is in string format
        if isinstance(receiver_public_key_pem, bytes):
            receiver_public_key_pem = receiver_public_key_pem.decode('utf-8')

        # Load the receiver's public key
        try:
            receiver_public_key = rsa.PublicKey.load_pkcs1(receiver_public_key_pem)
        except Exception as e:
            print(f"Error loading receiver public key: {e}")
            return jsonify({"error": f"Invalid receiver public key: {e}"}), 400

        # Encrypt the message using the receiver's public key
        try:
            encrypted_message = rsa.encrypt(message.encode('utf-8'), receiver_public_key)
            encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
        except Exception as e:
            print(f"Error encrypting message: {e}")
            return jsonify({"error": f"Message encryption failed: {e}"}), 500

        # Set expiry time for co-owner signing
        expiry_time = datetime.now() + timedelta(hours=24)

        # Handle co_owner_name (check if it exists)
        co_owner_id = None
        if co_owner_name:
            cursor.execute('SELECT id FROM users WHERE user_id = %s', (co_owner_name,))
            co_owner = cursor.fetchone()
            if co_owner:
                co_owner_id = co_owner['id']
            else:
                return jsonify({"error": "Invalid co-owner"}), 400

        # Insert the encrypted message into the database
        cursor.execute(
            '''
            INSERT INTO messages 
            (sender_id, receiver_id, co_owner_id,message, signature, receiver_public_key, co_owner_signed, expiry_time) 
            VALUES (%s, %s,%s, %s, %s, %s, %s, %s)
            ''',
            (
                sender_id,
                receiver_name,
                co_owner_id,
                encrypted_message_base64,
                encrypted_message_base64,
                receiver_public_key_pem,
                False,  # Co-owner signed status initially False
                expiry_time
            )
        )
        connection.commit()

        # Get the newly created message ID
        message_id = cursor.lastrowid

        connection.close()

        # Return the details of the encrypted message
        return jsonify({
            "encryptedMessage": encrypted_message_base64,
            "messageId": message_id,
            "CoOwnerId": co_owner_name,  # Optional, will be None if not provided
            "receiverId": receiver['user_id'],
            "expiryTime": expiry_time.strftime('%Y-%m-%d %H:%M:%S')  # Format expiry time for readability
        }), 200

    except Exception as e:
        print(f"Error in generate_signature: {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/verify_signature', methods=['GET'])
def verify_signature():
    # Check if user is logged in
    if 'user_id' not in session:
        return render_template("error.html", error="User not logged in")

    # Establish database connection
    connection = get_db_connection()
    if not connection:
        return render_template("error.html", error="Database connection failed")

    cursor = connection.cursor(dictionary=True)
    user_id = session['user_id']

    # Fetch the private key and public key for the user
    cursor.execute('SELECT private_key, public_key FROM users WHERE user_id = %s', (user_id,))
    user = cursor.fetchone()

    if not user:
        return render_template("error.html", error="User not found")

    # Decode private key if it's stored as bytes and clean it up
    private_key = user['private_key']
    if isinstance(private_key, bytes):
        private_key = private_key.decode('utf-8').strip()

    # Fetch messages where the user is the receiver and co_owner_id is NULL
    cursor.execute('''
        SELECT id, signature, sender_id, receiver_public_key 
        FROM messages 
        WHERE receiver_id = %s AND co_owner_id IS NULL
    ''', (user_id,))
    messages = cursor.fetchall()

    connection.close()

    # Pass cleaned private key, public key, and messages to the template
    return render_template(
        "verifysignature.html",
        private_key=private_key,
        user=user,
        public_key=user['public_key'],
        messages=messages
    )

@app.route('/unlock_message', methods=['GET', 'POST'])
def unlock_message():
    try:
        if request.method == 'GET':
            return render_template("unlock_message.html")

        elif request.method == 'POST':
            # Retrieve inputs
            message_id = request.form.get('message_id')
            private_key_data = request.form.get('private_key')

            if not message_id or not private_key_data:
                return render_template("error.html", error="Message ID or Private Key is missing")

            # Load the receiver's private key
            try:
                private_key = rsa.PrivateKey.load_pkcs1(private_key_data.encode('utf-8'))
                print("Private Key Loaded Successfully")
            except Exception as e:
                return render_template("error.html", error=f"Invalid Private Key: {e}")

            # Establish database connection
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            # Fetch the encrypted message from the database
            cursor.execute(
                '''
                SELECT receiver_id, message 
                FROM messages 
                WHERE id = %s
                ''',
                (message_id,)
            )
            message_record = cursor.fetchone()

            if not message_record:
                connection.close()
                return render_template("error.html", error="Message not found")

            # Verify that the current user is the intended recipient
            receiver_id = session.get('user_id')
            if receiver_id != message_record['receiver_id']:
                connection.close()
                return render_template("error.html", error="You are not the intended recipient of this message")

            # Decode and decrypt the message
            try:
                def add_padding(base64_string):
                    """Add padding to a Base64 string if it's missing."""
                    while len(base64_string) % 4 != 0:
                        base64_string += '='
                    return base64_string

                encrypted_message = base64.b64decode(add_padding(message_record['message']))
                print("Encrypted Message (Base64):", message_record['message'])
                print("Decoded Encrypted Message (Binary):", encrypted_message)

                decrypted_message = rsa.decrypt(encrypted_message, private_key).decode('utf-8')
                print("Message Decrypted Successfully")
            except rsa.DecryptionError as e:
                return render_template("error.html", error=f"Decryption failed: {e}")
            except Exception as e:
                return render_template("error.html", error=f"An unexpected error occurred: {e}")

            # On successful decryption, display the message
            connection.close()
            return render_template("message_display.html", message=decrypted_message)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return render_template("error.html", error=f"An unexpected error occurred: {str(e)}")

from datetime import datetime

@app.route('/add_signature', methods=['POST'])
def add_signature():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    try:
        data = request.json
        message_id = data.get('messageId')
        print(message_id)
        user_id = session['user_id']
        print(user_id)

        if not message_id:
            return jsonify({"error": "Message ID is required"}), 400

        # Connect to the database
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Fetch message details
        cursor.execute('SELECT * FROM messages WHERE id = %s', (message_id,))
        message = cursor.fetchone()
        print(message['co_owner_id'])
        cursor.execute('select id from users where user_id=%s',(user_id,))
        u_id=cursor.fetchall()
        print(u_id)

        if not message:
            connection.close()
            return jsonify({"error": "Message not found"}), 404

        # Check if the co-owner is authorized to sign the message
       # if message['co_owner_id'] != u_id:
           # connection.close()
           # return jsonify({"error": "You are not authorized to sign this message"}), 403

        # Check if the signing period has expired
        expiry_time = message.get('expiry_time')
        current_time = datetime.now()
        if expiry_time and current_time > expiry_time:
            connection.close()
            return jsonify({"error": "The signing period for this message has expired"}), 400

        # Check if the co-owner has already signed the message
        cursor.execute(
            'SELECT * FROM message_signatures WHERE message_id = %s AND co_owner_id = %s',
            (message_id, user_id)
        )
        if cursor.fetchone():
            connection.close()
            return jsonify({"error": "You have already signed this message"}), 400

        # Fetch user's private key
        cursor.execute('SELECT private_key FROM users WHERE user_id = %s', (user_id,))
        user = cursor.fetchone()

        if not user:
            connection.close()
            return jsonify({"error": "User not found"}), 404

        private_key = rsa.PrivateKey.load_pkcs1(user['private_key'])

        # Sign the message
        signature = rsa.sign(message['signature'].encode('utf-8'), private_key, 'SHA-256')
        signature_base64 = base64.b64encode(signature).decode('utf-8')

        # Add the signature to the database
        cursor.execute(
            'INSERT INTO message_signatures (message_id, co_owner_id, signature,receiver_id,sender_id) VALUES (%s, %s, %s,%s,%s)',
            (message_id, user_id, signature_base64,message['receiver_id'],message['sender_id'])
        )

        # Mark the message as signed by the co-owner
        cursor.execute(
            'UPDATE messages SET co_owner_signed = TRUE WHERE id = %s',
            (message_id,)
        )

        connection.commit()
        connection.close()

        return jsonify({"success": "Signature added successfully!"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500



@app.route('/verify_multi_signature', methods=['GET', 'POST'])
def verify_multi_signature():
    if 'user_id' not in session:
        return render_template("error.html", error="User not logged in")

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Fetch user's private key
        user_id = session['user_id']
        cursor.execute('SELECT private_key FROM users WHERE user_id = %s', (user_id,))
        user = cursor.fetchone()

        if not user:
            return render_template("error.html", error="User not found")

        private_key_pem = user['private_key']
        if isinstance(private_key_pem, bytes):
            private_key_pem = private_key_pem.decode('utf-8')

        if request.method == 'GET':
            # Fetch data from `message_signatures` table and `messages` table
            cursor.execute(
                '''
                SELECT ms.message_id, ms.sender_id, ms.co_owner_id, ms.signature
                FROM message_signatures ms where receiver_id=%s
                
                ''',
                (user_id,)
            )
            messages = cursor.fetchall()

            # Render the form with private key and message data
            return render_template(
                'verify_multi_signature.html',
                private_key=private_key_pem,
                messages=messages
            )

        elif request.method == 'POST':
            # Get form data
            message_id = request.form.get('message_id')
            private_key_input = request.form.get('private_key')

            if not message_id or not private_key_input:
                return render_template(
                    "verify_multi_signature.html",
                    error="Message ID and Private Key are required",
                    private_key=private_key_pem,
                    messages=[]
                )

            # Load the private key entered by the user
            try:
                private_key = rsa.PrivateKey.load_pkcs1(private_key_input.encode('utf-8'))
            except Exception as e:
                return render_template(
                    "verify_multi_signature.html",
                    error=f"Invalid private key: {e}",
                    private_key=private_key_pem,
                    messages=[]
                )

            # Fetch the message details
            cursor.execute(
                '''
                SELECT m.message
                FROM messages m
                WHERE m.id = %s
                ''',
                (message_id,)
            )
            message_record = cursor.fetchone()

            if not message_record:
                return render_template(
                    "verify_multi_signature.html",
                    error="Message not found",
                    private_key=private_key_pem,
                    messages=[]
                )

            # Decode and decrypt the message
            try:
                def add_padding(base64_string):
                    """Add padding to a Base64 string if it's missing."""
                    while len(base64_string) % 4 != 0:
                        base64_string += '='
                    return base64_string

                encrypted_message = base64.b64decode(add_padding(message_record['message']))
                decrypted_message = rsa.decrypt(encrypted_message, private_key).decode('utf-8')
                print("Message Decrypted Successfully")
            except rsa.DecryptionError as e:
                return render_template(
                    "verify_multi_signature.html",
                    error=f"Decryption failed: {e}",
                    private_key=private_key_pem,
                    messages=[]
                )
            except Exception as e:
                return render_template(
                    "verify_multi_signature.html",
                    error=f"An unexpected error occurred during decryption: {e}",
                    private_key=private_key_pem,
                    messages=[]
                )

            return render_template("message_display.html", message=decrypted_message)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return render_template("error.html", error=f"An unexpected error occurred: {str(e)}")

@app.route('/get_messages_to_sign', methods=['GET'])
def get_messages_to_sign():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    co_owner_id = session['id']
    print(co_owner_id)
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Fetch messages where the logged-in user is a co-owner
        cursor.execute(
            '''
            SELECT id, sender_id, message
            FROM messages
            WHERE co_owner_id = %s
            ''',
            (co_owner_id,)
        )
        messages = cursor.fetchall()
        connection.close()

        return jsonify({"messages": messages})
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/get_co_owner_messages', methods=['GET'])
def get_co_owner_messages():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    co_owner_id = session['user_id']

    connection = get_db_connection()
    if not connection:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = connection.cursor(dictionary=True)

    try:
        # Fetch the user's ID from the `users` table
        cursor.execute('''SELECT id FROM users WHERE user_id = %s''', (co_owner_id,))
        user_record = cursor.fetchone()
        if not user_record:
            return jsonify({"error": "Co-owner not found"}), 400

        co_id = user_record['id']

        # Fetch messages assigned to the co-owner
        cursor.execute(
            '''
            SELECT id, sender_id, message, expiry_time 
            FROM messages 
            WHERE co_owner_id = %s AND co_owner_signed = FALSE
            ''', (co_id,)
        )
        messages = cursor.fetchall()

        current_time = datetime.now()

        # Add remaining time for each message
        for message in messages:
            if message['expiry_time']:
                expiry_time = message['expiry_time']
                remaining_time = (expiry_time - current_time).total_seconds()
                if remaining_time > 0:
                    message['remaining_time'] = remaining_time  # Time in seconds
                else:
                    message['remaining_time'] = 0  # Message expired

        connection.close()
        return jsonify({"messages": messages}), 200
    except Exception as e:
        print(f"Error fetching co-owner messages: {e}")
        return jsonify({"error": "Failed to fetch messages"}), 500

if __name__ == "__main__":
    app.run(debug=True)