#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource

from config import app, db, api
from models import User

def user_to_dict(user):
    """
    Helper function to convert a User object to a dictionary
    excluding sensitive information like the password hash.
    """
    return {
        'id': user.id,
        'username': user.username
    }

class ClearSession(Resource):
    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()

        # Check if the user already exists
        if User.query.filter_by(username=json['username']).first():
            return {"error": "User already exists"}, 400

        # Create new user and hash the password
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']  # Use setter method to hash
        db.session.add(user)
        db.session.commit()

        # Save user id in session
        session['user_id'] = user.id

        # Return the user object as a dictionary
        return jsonify(user_to_dict(user)), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify(user_to_dict(user)), 200
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        user = User.query.filter_by(username=json['username']).first()

        if user and user.authenticate(json['password']):
            session['user_id'] = user.id
            return jsonify(user_to_dict(user)), 200

        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        session.clear()  # Clear the session
        return {}, 204

# Add resources to the API
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
