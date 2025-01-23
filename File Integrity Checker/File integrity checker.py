import hashlib
import os
import json

class FileIntegrityChecker:
    def __init__(self, directory, hash_file="file_hashes.json"):
        self.directory = directory
        self.hash_file = hash_file

    def calculate_hash(self, file_path):
        """Calculate the SHA-256 hash of a file."""
        hash_func = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

    def scan_files(self):
        """Scan all files in the directory and calculate their hashes."""
        file_hashes = {}
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hashes[file_path] = self.calculate_hash(file_path)
        return file_hashes

    def save_hashes(self, file_hashes):
        """Save file hashes to a JSON file."""
        try:
            with open(self.hash_file, "w") as f:
                json.dump(file_hashes, f, indent=4)
            print(f"File hashes saved to {self.hash_file}")
        except Exception as e:
            print(f"Error saving hashes: {e}")

    def load_hashes(self):
        """Load file hashes from the JSON file."""
        try:
            if os.path.exists(self.hash_file):
                with open(self.hash_file, "r") as f:
                    return json.load(f)
            else:
                print(f"Hash file {self.hash_file} not found. Starting fresh.")
                return {}
        except Exception as e:
            print(f"Error loading hashes: {e}")
            return {}

    def check_integrity(self):
        """Compare current file hashes with the saved ones."""
        old_hashes = self.load_hashes()
        current_hashes = self.scan_files()

        created_files = []
        modified_files = []
        deleted_files = []

        for file_path, current_hash in current_hashes.items():
            old_hash = old_hashes.get(file_path)
            if old_hash is None:
                created_files.append(file_path)
            elif old_hash != current_hash:
                modified_files.append(file_path)

        for file_path in old_hashes:
            if file_path not in current_hashes:
                deleted_files.append(file_path)

        # Display results
        if created_files:
            print("\nCreated files:")
            for file in created_files:
                print(f"  - {file}")

        if modified_files:
            print("\nModified files:")
            for file in modified_files:
                print(f"  - {file}")

        if deleted_files:
            print("\nDeleted files:")
            for file in deleted_files:
                print(f"  - {file}")

        if not (created_files or modified_files or deleted_files):
            print("\nNo changes detected.")

        # Save the updated hashes
        self.save_hashes(current_hashes)

if __name__ == "__main__":
    directory_to_monitor = input("Enter the directory to monitor: ")
    checker = FileIntegrityChecker(directory_to_monitor)
    checker.check_integrity()
