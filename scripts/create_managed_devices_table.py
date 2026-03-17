import os
import sys

from src.core.database import db_manager
#from src.models.database import Base

# Add the project root to sys.path
sys.path.append(os.getcwd())


def create_table():
    print("Creating managed_devices table in SQLite...")
    try:
        # Initialize the engine and metadata
        db_manager.initialize()
        print("Success! Table created or already exists.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    create_table()
