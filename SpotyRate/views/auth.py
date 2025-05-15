"""
Django Views for Spotify OAuth2 Authentication and User Management
"""

import os
import logging
import requests
import dotenv
from django.shortcuts import redirect
from django.http import JsonResponse
from django.contrib.auth import logout
from django.urls import reverse
from ..models import SpotifyUser

# Initialize logger
logger = logging.getLogger(__name__)

# Load environment variables
dotenv.load_dotenv()

# Spotify API configuration
SPOTIFY_CLIENT_ID = os.getenv("CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SPOTIFY_REDIRECT_URI = "http://127.0.0.1:8000/callback/"
SPOTIFY_AUTH_URL = "https://accounts.spotify.com/authorize"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_API_BASE = "https://api.spotify.com/v1/"
SPOTIFY_SCOPES = "user-read-private user-read-email"

# Session keys
SESSION_ACCESS_TOKEN = "spotify_access_token"
SESSION_REFRESH_TOKEN = "spotify_refresh_token"


def spotify_login(request) -> redirect:
    """
    Redirect users to Spotify's authorization page.

    Args:
        request: Django request object

    Returns:
        redirect: Redirect response to Spotify login
    """
    auth_params = {
        "response_type": "code",
        "client_id": SPOTIFY_CLIENT_ID,
        "redirect_uri": SPOTIFY_REDIRECT_URI,
        "scope": SPOTIFY_SCOPES,
    }

    auth_url = f"{SPOTIFY_AUTH_URL}?{requests.compat.urlencode(auth_params)}"
    return redirect(auth_url)


def spotify_callback(request) -> redirect:
    """
    Handle Spotify OAuth2 callback and user data management.

    Args:
        request: Django request object with authorization code

    Returns:
        redirect: To dashboard or error response
    """
    # Validate authorization code
    if not (code := request.GET.get("code")):
        logger.error("Authorization code missing in callback")
        return JsonResponse({"error": "Authorization code required"}, status=400)

    try:
        # Step 1: Exchange authorization code for an access token
        token_data = _exchange_code_for_token(code)

        # Step 2: Fetch user data from Spotify API
        user_data = _get_spotify_user_data(token_data["access_token"])

        # Step 3: Create or update a local user record
        user = _sync_spotify_user(user_data)

        # Step 4: Manage session data
        _handle_session_data(request, token_data)

        logger.info(f"Successful Spotify login for user {user.spotify_id}")
        return redirect(reverse("dashboard"))

    except (KeyError, requests.RequestException) as e:
        logger.error(f"Spotify callback error: {str(e)}")
        return JsonResponse({"error": "Authentication failed"}, status=500)


def _exchange_code_for_token(code: str) -> dict:
    """Exchange authorization code for an access token."""
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": SPOTIFY_REDIRECT_URI,
        "client_id": SPOTIFY_CLIENT_ID,
        "client_secret": SPOTIFY_CLIENT_SECRET,
    }

    response = requests.post(SPOTIFY_TOKEN_URL, data=payload)
    response.raise_for_status()
    return response.json()


def _get_spotify_user_data(access_token: str) -> dict:
    """Retrieve user profile data from Spotify API."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{SPOTIFY_API_BASE}me", headers=headers)
    response.raise_for_status()
    return response.json()


def _sync_spotify_user(user_data: dict) -> SpotifyUser:
    """Create or update SpotifyUser record with API data."""
    user_data_map = {
        "spotify_id": user_data["id"],
        "display_name": user_data.get("display_name", "Unknown"),
        "email": user_data.get("email", ""),
        "profile_image_url": user_data.get("images", [{}])[0].get("url") if user_data.get("images") else None
    }

    user, created = SpotifyUser.objects.update_or_create(
        spotify_id=user_data_map["spotify_id"],
        defaults=user_data_map
    )

    logger.debug(f"{'Created' if created else 'Updated'} user {user.spotify_id}")
    return user


def _handle_session_data(request, token_data: dict):
    """Store authentication tokens in session."""
    request.session[SESSION_ACCESS_TOKEN] = token_data["access_token"]
    if refresh_token := token_data.get("refresh_token"):
        request.session[SESSION_REFRESH_TOKEN] = refresh_token


def session_logout(request) -> JsonResponse:
    """
    Terminate both Django and Spotify sessions.

    Args:
        request: Django request object

    Returns:
        JsonResponse: Logout confirmation
    """
    # Clear Django authentication
    logout(request)

    # Flush session data
    request.session.flush()

    # Redirect to Spotify's global logout
    spotify_logout_url = "https://accounts.spotify.com/en/logout"
    logger.info("User logged out successfully")
    return JsonResponse({
        "message": "Logged out successfully",
        "spotify_logout": spotify_logout_url
    })


def refresh_spotify_token(request) -> JsonResponse:
    """
    Refresh expired Spotify access token using refresh token.

    Args:
        request: Django request object

    Returns:
        JsonResponse: New access token or error
    """
    if not (refresh_token := request.session.get(SESSION_REFRESH_TOKEN)):
        logger.warning("Refresh token missing in token refresh attempt")
        return JsonResponse({"error": "No refresh token available"}, status=401)

    try:
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": SPOTIFY_CLIENT_ID,
            "client_secret": SPOTIFY_CLIENT_SECRET,
        }

        response = requests.post(SPOTIFY_TOKEN_URL, data=payload)
        response.raise_for_status()
        token_data = response.json()

        request.session[SESSION_ACCESS_TOKEN] = token_data["access_token"]
        logger.debug("Successfully refreshed Spotify access token")
        return JsonResponse({"access_token": token_data["access_token"]})

    except requests.RequestException as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return JsonResponse({"error": "Token refresh failed"}, status=400)
