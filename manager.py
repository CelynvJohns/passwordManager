# allows for mysql db connection
import mysql.connector
# allows for error message specifics
from mysql.connector import Error
#high-level symmetric encrpytion tool uses AES (Advanced Encryption Standards) algrithim in CBC (Cipher Block Chaining) mode and PKCs7 padding. 
# basically simple & easy interface for data encryption and decryption
from cryptography.fernet import Fernet
#allows for passwords to be inputed securely (when you enter the password you can't see it)
import getpass
# allows for reading / writing to files
import os

# Generate a key for encryption and decryption
def generate_key():
    return Fernet.generate_key()

# Load key from a file or generate a new one if file does not exist
def load_or_generate_key():
    # sets the file name needed
    key_file = 'secret.key'
    #checks if the file exists
    if os.path.exists(key_file):
        # if it does it reads what is in the file
        with open(key_file, 'rb') as key_file:
            key = key_file.read()
    else:
        # if it doesn't exist it creates a key in the file
        key = generate_key()
        with open(key_file, 'wb') as key_file:
            key_file.write(key)
    return key

# Encrypt data using the generated key
def encrypt_message(message, key):
    fernet = Fernet(key)
    # takes the generated key and uses Fernet to encrypt the message
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Decrypt data using the key
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    # takes the generated key and uses Fernet to decrypt the message
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

# Connect to MySQL database
def connect_to_mysql(host, user, password, database):
    try:
        # attempts to connect to db using defined data
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        # lets you know if you connected
        if connection.is_connected():
            print("Connected to MySQL database")
            return connection
    # lets you know why you could not connect
    except Error as e:
        print(f"Error connecting to MySQL database: {e}")
        return None

# Create table to store passwords
def create_table(connection):
    try:
        cursor = connection.cursor()
        # creates the table using SQL
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INT AUTO_INCREMENT PRIMARY KEY,
                website VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                password BLOB NOT NULL
            )
        """)
        # commits the table execution
        connection.commit()
        #lets you know it was created
        print("Table 'passwords' created successfully")
    # lets you know why it couldn't be created
    except Error as e:
        print(f"Error creating table: {e}")

# Store password in database
def store_password(connection, website, username, password, key):
    encrypted_password = encrypt_message(password, key)
    try:
        cursor = connection.cursor()
        # how the information is inputed into the database
        sql = "INSERT INTO passwords (website, username, password) VALUES (%s, %s, %s)"
        # setting up the data
        data = (website, username, encrypted_password)
        # executes and then commits / finalizes the data
        cursor.execute(sql, data)
        connection.commit()
        # tells you if your password is stored
        print("Password stored successfully")
    # lets you know why the password wasn't stored
    except Error as e:
        print(f"Error storing password: {e}")

# Retrieve password from database
def retrieve_password(connection, website, username, key):
    try:
        cursor = connection.cursor()
        # how the information is checked in the database
        sql = "SELECT password FROM passwords WHERE website = %s AND username = %s"
        # defines the data needed
        data = (website, username)
        # executes and then fetches the data
        cursor.execute(sql, data)
        record = cursor.fetchone()
        if record:
            # if there is a password it retrieves it
            encrypted_password = record[0]
            decrypted_password = decrypt_message(encrypted_password, key)
            print(f"Password for {website}: {decrypted_password}")
        else:
            # lets you know if there is no password matching the criteria
            print(f"No password found for {website}, {username}")
    # tells you if there was an error
    except Error as e:
        print(f"Error retrieving password: {e}")

# Delete password from database
def delete_password(connection, website, username):
    try:
        cursor = connection.cursor()
        # how it tells sql to delete the password
        sql = "DELETE FROM passwords WHERE website = %s AND username = %s"
        # defines the data needed to delete the password
        data = (website, username)
        # executes and then commits the change
        cursor.execute(sql, data)
        connection.commit()
        # tells you the password was deleted
        print(f"Password for {website}, {username} deleted successfully")
    # tells you if there was an error
    except Error as e:
        print(f"Error deleting password: {e}")

# Main function
if __name__ == "__main__":
    # MySQL database configuration
    host = "localhost"
    user = "root"
    password = " "
    database = "password_manager"

    # Connect to MySQL
    connection = connect_to_mysql(host, user, password, database)

    if connection:
        # Create table if not exists
        create_table(connection)

        # Load or generate encryption key
        key = load_or_generate_key()
        #creates a while loop to allow for user to use password manager as much as they want
        while True:
            # gives the options for the user and a brief explaination
            print("\nMenu:")
            print("1. Store Password")
            print("2. Retrieve Password")
            print("3. Delete Password")
            print("4. Exit")
            # how the program stores user input
            choice = input("Enter your choice (1/2/3/4): ")

            #if the user wants to store password
            if choice == "1":
                #asks for the data needed
                website = input("Enter website: ")
                username = input("Enter username: ")
                #uses getpass to hide password
                password = getpass.getpass("Enter password: ")
                #uses store_password function
                store_password(connection, website, username, password, key)
                
            # if the user wants to retrieve a password
            elif choice == "2":
                #gets data from user
                website = input("Enter website: ")
                username = input("Enter username: ")
                #uses retrieve_password function
                retrieve_password(connection, website, username, key)
                
            # if the user wants to delete a password
            elif choice == "3":
                # gets data from user
                website = input("Enter website: ")
                username = input("Enter username: ")
                # uses delete_password function
                delete_password(connection, website, username)
                
            # if the user wants to stop the loop
            elif choice == "4":
                # lets you know loop is stopping then exits
                print("Exiting...")
                break
            
            # requires user to input a valid option (1,2,3, or 4)
            else:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")

        # Close MySQL connection
        if connection.is_connected():
            connection.close()
            print("MySQL connection is closed")
