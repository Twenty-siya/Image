import os
from tkinter import Tk, filedialog, Button, Label, messagebox
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
def encrypt_image():
    global key

    # Select image file
    file_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return

    # Open and convert image to RGB
    image = Image.open(file_path).convert("RGB")
    width, height = image.size

    # Convert image to bytes
    image_bytes = np.array(image).tobytes()

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Encrypt image bytes using AES in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(image_bytes, AES.block_size))

    # Save encrypted data to a file
    encrypted_file = file_path + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(iv + encrypted_bytes)

    messagebox.showinfo("Success", f"Image encrypted and saved as {encrypted_file}")

    # Store dimensions for decryption
    global image_info
    image_info = (width, height)

def decrypt_image():
    global key, image_info

    # Select encrypted file
    file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc")])
    if not file_path:
        return

    # Read encrypted file
    with open(file_path, "rb") as f:
        iv = f.read(16)  # Extract the IV
        encrypted_bytes = f.read()

    # Decrypt image data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

    # Retrieve image dimensions
    width, height = image_info

    # Convert bytes back to an image
    image_array = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape((height, width, 3))
    image = Image.fromarray(image_array)

    # Save the decrypted image
    decrypted_file = file_path.replace(".enc", "_decrypted.jpg")
    image.save(decrypted_file)

    messagebox.showinfo("Success", f"Decrypted image saved as {decrypted_file}")


# Generate a random AES key (16 bytes for AES-128)
key = os.urandom(16)
image_info = None  # Stores width and height for decryption

# Create GUI window
root = Tk()
root.title("Image Encryption & Decryption")
root.geometry("400x400")

Label(root, text="Image Encryption & Decryption using AES", font=("Arial", 12)).pack(pady=10)

# Buttons for encryption and decryption
Button(root, text="Encrypt Image", command=encrypt_image, width=20, height=2).pack(pady=5)
Button(root, text="Decrypt Image", command=decrypt_image, width=20, height=2).pack(pady=5)

# Run GUI loop
root.mainloop()
