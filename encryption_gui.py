import os #for OS operations like random number generation
from Crypto.Cipher import AES #pycryptodome AES algorithm 
from Crypto.Util.Padding import pad, unpad #PKCS7 padding
from Crypto.Random import get_random_bytes #for random key generation
from Crypto.Protocol.KDF import PBKDF2 #PBKDF2 key derivation function for a given password 
import tkinter as tk #for GUI building
from tkinter import filedialog, messagebox, simpledialog #file dialogue boxes, message boxes, etc.

#select file path for encryption/decryption
def file_select():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

#use GUI operations to encrypt a file
def encrypt_gui():
    #get info entered by user
    file_name = file_entry.get()
    password = password_entry.get()
    hex_key = key_entry.get()
    use_key = use_key_var.get()
    delete_original = delete_var.get()

    #if file doesn't exist
    if not file_name or not os.path.exists(file_name):
        messagebox.showerror("Error", "Please select a valid file.")
        return
        
    encrypted_file = file_name + '.aes' #encrypted file will have a .aes extension

    #confirm overwrite if encrypted file name already exists
    if os.path.exists(encrypted_file):
        overwrite = messagebox.askyesno("Confirm Overwrite", f"{encrypted_file} already exists. Do you want to overwrite it?")
        if not overwrite:
            messagebox.showinfo("Cancelled", "Encryption cancelled.")
            return    

    #key for encryption
    if use_key and len(hex_key) == 64:
        key = bytes.fromhex(hex_key)
        salt = os.urandom(16) #random salt (not used in this case)
    #password for encryption
    elif not use_key and password:
        salt = os.urandom(16) #random salt
        key = PBKDF2(password, salt, dkLen=32, count=1000000) #generate key using PBKDF2 key derivation function
    #generate random key if nothing provided
    else:
        key = get_random_bytes(32) 
        salt = os.urandom(16) #random salt (not used in this case)
        #put key in user's clipboard and notify them
        root.clipboard_clear()
        root.clipboard_append(key.hex())
        messagebox.showinfo("Key Generated",
                            "Neither key nor password provided. A random key has been generated and copied to your clipboard. Please save it securely.")
        use_key = True  #we're using a key since one was generated

    #random initialization vector
    iv = os.urandom(16)

    #encrypt data, write to file with salt and iv
    try:
        with open(file_name, 'rb') as f_in:
            file_data = f_in.read()
            cipher = AES.new(key, AES.MODE_CBC, iv) #AES in CBC mode
            #encrypt
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            encrypted_file = file_name + '.aes'
            
            #write encrypted data to file
            with open(encrypted_file, 'wb') as f_out:
                f_out.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", "File encrypted successfully.")

        #confirm deletion of original file
        if delete_original:
            confirm_delete = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {file_name}?")
            if confirm_delete:
                os.remove(file_name)
                messagebox.showinfo("Success", "Original file deleted.")
            else:
                messagebox.showinfo("Cancelled", "File deletion cancelled.")
    #display error if one arises
    except Exception as e:
        messagebox.showerror("Error", str(e))

#use GUI operations to decrypt a file
def decrypt_gui():
    #get info entered by user
    file_name = file_entry.get()
    password = password_entry.get()
    hex_key = key_entry.get()
    use_key = use_key_var.get()
    delete_original = delete_var.get()

    #if file doesn't exist
    if not file_name or not os.path.exists(file_name):
        messagebox.showerror("Error", "Please select a valid file.")
        return

    decrypted_file = file_name.rsplit('.aes', 1)[0] #decrypted file will drop the .aes expension

    # Check if the decrypted file already exists
    if os.path.exists(decrypted_file):
        overwrite = messagebox.askyesno("Confirm Overwrite", f"{decrypted_file} already exists. Do you want to overwrite it?")
        if not overwrite:
            messagebox.showinfo("Cancelled", "Decryption cancelled.")
            return
    
    #read salt and iv, use to decrypt data in file  
    try:
        with open(file_name, 'rb') as f_in:
            salt = f_in.read(16)  #first 16 bytes are salt
            iv = f_in.read(16)  #next 16 bytes are iv
            encrypted_data = f_in.read()
            
            #hex key for decryption
            if use_key:
                if len(hex_key) != 64:
                    messagebox.showerror("Error", "Key must be 64 hexadecimal characters (32 bytes).")
                    return
                key = bytes.fromhex(hex_key)
            #password for decryption
            else:
                if not password:
                    messagebox.showerror("Error", "Please enter a password.")
                    return
                key = PBKDF2(password, salt, dkLen=32, count=1000000)

            cipher = AES.new(key, AES.MODE_CBC, iv) #AES in CBC mode
            #decrypt
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            decrypted_file = file_name.rsplit('.aes', 1)[0]

            #write decrypted data to file
            with open(decrypted_file, 'wb') as f_out:
                f_out.write(decrypted_data)

        messagebox.showinfo("Success", "File decrypted successfully.")

        #confirm deletion of original file
        if delete_original:
            confirm_delete = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {file_name}?")
            if confirm_delete:
                os.remove(file_name)
                messagebox.showinfo("Success", "Original file deleted.")
            else:
                messagebox.showinfo("Cancelled", "File deletion cancelled.")
    #display error if one arises (usually due to incorrect key/password)      
    except Exception as e:
        messagebox.showerror("Error", str(e) + " (Likely Incorrect Password)")
        
#main window
root = tk.Tk()
root.title("CIS 628 AES File Encryption/Decryption Tool")

#file selection window/button
tk.Label(root, text="File:").grid(row=0, column=0, padx=10, pady=10)
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=file_select).grid(row=0, column=2, padx=10, pady=10)

#password field
tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*", width=50)
password_entry.grid(row=1, column=1, padx=10, pady=10)

#key field
tk.Label(root, text="Key (Hex):").grid(row=2, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, show="*", width=50)
key_entry.grid(row=2, column=1, padx=10, pady=10)

#use key checkbox
use_key_var = tk.IntVar()
use_key_check = tk.Checkbutton(root, text="Use Key for Encryption/Decryption", variable=use_key_var)
use_key_check.grid(row=4, column=1, sticky='w', padx=10, pady=10)

#delete original file checkbox
delete_var = tk.IntVar()
delete_check = tk.Checkbutton(root, text="Securely Delete Original File", variable=delete_var)
delete_check.grid(row=5, column=1, sticky='w', padx=10, pady=10)

#encrypt, decrypt buttons
tk.Button(root, text="Encrypt", command=lambda: encrypt_gui()).grid(row=4, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt", command=lambda: decrypt_gui()).grid(row=4, column=2, padx=10, pady=10)

#start by opening main GUI
root.mainloop()