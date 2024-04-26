#!/usr/bin/env python3
"""usr authorization"""

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    """Return homepage"""
    return jsonify({'message': 'Bienvenue'})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """Account creation page"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({'email': email, 'message': 'user created'})
    except ValueError:
        return jsonify({'message': 'email already registered'}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """Account login response"""
    email = request.form.get('email')
    password = request.form.get('password')
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    res = jsonify({'email': email, 'message': 'logged in'})
    res.set_cookie('session_id', session_id)
    return res


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """Redirect to home"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """User profile info"""
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({'email': user.email})


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
   """Token to reset password """
    email = request.form.get('email')
    reset_token = None
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        reset_token = None
    if reset_token is None:
        abort(403)
    return jsonify({'email': email, 'reset_token': reset_token})


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """ Passsword updated messsage"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_pass = request.form.get('new_password')
    has_pass_changed = False
    try:
        AUTH.update_password(reset_token, new_pass)
        has_pass_changed = True
    except ValueError:
        has_pass_changed = False
    if not has_pass_changed:
        abort(403)
    return jsonify({'email': email, 'message': 'Password updated'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000', debug=True)
