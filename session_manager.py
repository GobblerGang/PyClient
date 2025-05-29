# session_manager.py
from flask import session
from utils.secure_master_key import MasterKey
from utils.dataclasses import PAC
import json

def set_session_value(key, value):
    """
    Store a value in the session and track the key for later clearing.
    """
    session[key] = value
    session_keys = session.get('session_keys', set())
    if isinstance(session_keys, list):
        session_keys = set(session_keys)
    session_keys.add(key)
    session['session_keys'] = list(session_keys)

def get_session_value(key):
    """
    Retrieve a value from the session by key.
    """
    return session.get(key)

def clear_session():
    """
    Clears sensitive session data.
    Called on logout or app exit.
    """
    MasterKey().clear()
    session_keys = session.get('session_keys', [])
    for key in session_keys:
        session.pop(key, None)
    session.pop('session_keys', None)

# def get_pacs_from_session():
#     """Retrieve PACs from session and deserialize to PAC objects."""
#     pacs_json = session.get('pacs', [])
#     if isinstance(pacs_json, str):
#         pacs_json = json.loads(pacs_json)
#     return [PAC.from_json(pac) for pac in pacs_json]

# def get_private_keys_from_session():
#     """Retrieve user's private keys from session (assumes keys are stored in session)."""
#     return session.get('private_keys', {})
