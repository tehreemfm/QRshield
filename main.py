import os
import logging
from qr_decoder import decode_qr
from url_checker import sus_url

logging.basicConfig(
    filename='scan_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

def main():
    folder = "test_images"
    if not os.path.exists(folder):
        print("Folder doesn't exist")
        return

    images = [f for f in os.listdir(folder) if f.lower().endswith((".jpg", ".png", ".jpeg"))]
    if not images:
        print("No images found")
        return

    for img_file in images:
        img_path = os.path.join(folder, img_file)
        print(f"\n[>>] Processing: {img_file} ")
        url = decode_qr(img_path)

        if url:
            result = sus_url(url)

            print(f"[RESULT] {result['risk']}")
            for reason in result['reasons']:
                print(" -", reason)

            logging.info(
                f"FILE: {img_file} | URL: {url} | RESULT: {result['risk']} |"
                f"REASONS: {','.join(result['reasons'])}"
            )
        else:
            print(f"[RESULT] {img_file} NOT FOUND or failed to decode")

if __name__ == "__main__":
    main()