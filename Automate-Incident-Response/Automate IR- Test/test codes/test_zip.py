    
import shutil
from datetime import datetime
import os

def main():
    
    today = datetime.now().strftime("%m-%d")
    zip_file_path = f"C:/Users/prajs_28/Downloads/Compromised_logs_{today}"
    zip_attachment = f"C:/Users/prajs_28/Downloads/Compromised_logs_{today}.zip"
    shutil.make_archive(zip_attachment, 'zip', zip_file_path)

if __name__ == "__main__":
    main()