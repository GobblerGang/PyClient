# session_manager.py
from flask import session
from utils.secure_master_key import MasterKey
from utils.dataclasses import PAC
import json

def clear_session():
    """
    Clears sensitive session data.
    Called on logout or app exit.
    """
    MasterKey().clear()
    session.pop('pacs', None)

def get_pacs_from_session():
    """Retrieve PACs from session and deserialize to PAC objects."""
    pacs_json = session.get('pacs', [])
    if isinstance(pacs_json, str):
        pacs_json = json.loads(pacs_json)
    return [PAC.from_json(pac) for pac in pacs_json]

def get_private_keys_from_session():
    """Retrieve user's private keys from session (assumes keys are stored in session)."""
    return session.get('private_keys', {})
