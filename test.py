"""
clear_ledgers.py
----------------
Deletes ALL LedgerEntry and Ledger records from the database.
Users and Connections are NOT touched.

Run from your project root:
    python clear_ledgers.py
"""

from app import app, db
from models import LedgerEntry, Ledger


def clear_ledger_data():
    with app.app_context():
        print("Starting ledger data cleanup...")

        # Step 1: Null out all self-referential connected_entry_id links first
        # to avoid circular FK / constraint errors during deletion
        print("  - Clearing connected_entry_id references...")
        LedgerEntry.query.update(
            {LedgerEntry.connected_entry_id: None},
            synchronize_session=False
        )
        db.session.flush()

        # Step 2: Delete all ledger entries
        entry_count = LedgerEntry.query.count()
        LedgerEntry.query.delete(synchronize_session=False)
        print(f"  - Deleted {entry_count} ledger entries.")

        # Step 3: Delete all ledgers
        ledger_count = Ledger.query.count()
        Ledger.query.delete(synchronize_session=False)
        print(f"  - Deleted {ledger_count} ledgers.")

        # Step 4: Commit everything
        db.session.commit()
        print("Done! All ledger data cleared. Users and connections are untouched.")


if __name__ == '__main__':
    confirm = input(
        "WARNING: This will permanently delete ALL ledgers and entries.\n"
        "Type 'yes' to confirm: "
    )
    if confirm.strip().lower() == 'yes':
        clear_ledger_data()
    else:
        print("Aborted. No data was deleted.")
        