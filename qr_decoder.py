from pyzbar.pyzbar import decode
from PIL import Image

def decode_qr(image_path):
    """
    Decodes the QR code found in an image

    Args:
        image_path (str): Path to the image.

    Returns:
        str or None: decoded QR code or None if not found
    """
    try:
        img = Image.open(image_path)
        decoded_objects = decode(img)

        if decoded_objects:
            qr_data = decoded_objects[0].data.decode('utf-8')
            print(f"[INFO] QR Code Detected: {qr_data}")
            return qr_data
        else:
            print("[ALERT] QR Code Not Detected.")
            return None

    except Exception as e:
        print(f"[ERROR] Unable to scan QR code {e}")
        return None