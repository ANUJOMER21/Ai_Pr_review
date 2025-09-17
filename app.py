import streamlit as st
from datetime import datetime, timedelta
from pathlib import Path
import os  # For key file check
import concurrent.futures  # For async

# Local imports (fixed)
from config.settings import CSS, PAGE_CONFIG
from core.database import DatabaseManager
from core.notifications import NotificationManager
from core.managers import UserManager, ReviewManager, EnhancedAuthManager

from ui.components import authenticate_user, show_login_page
from ui.pages import main_pages

# Setup logging
from utils.logger import setup_logging
setup_logging()

# Page config
st.set_page_config(**PAGE_CONFIG)
st.markdown(CSS, unsafe_allow_html=True)

# Initialize session state and managers
@st.cache_resource
def init_managers():
    db = DatabaseManager()
    return {
        'db_manager': db,
        'user_manager': UserManager(db),
        'auth_manager': EnhancedAuthManager(db),
        'notification_manager': NotificationManager(db),
        'review_manager': ReviewManager(db)
    }

managers = init_managers()
for key, mgr in managers.items():
    st.session_state[key] = mgr

# Session state init
if 'selected_page' not in st.session_state:
    st.session_state.selected_page = "🏠 Dashboard"
if 'show_review_modal' not in st.session_state:
    st.session_state.show_review_modal = False
if 'selected_review' not in st.session_state:
    st.session_state.selected_review = None
if 'selected_repo' not in st.session_state:
    st.session_state.selected_repo = None
if 'session_id' not in st.session_state:
    st.session_state.session_id = None

# Auth check
current_user = authenticate_user()
if not current_user:
    show_login_page()
else:
    main_pages(current_user)