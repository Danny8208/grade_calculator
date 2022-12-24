import json
import sys

from dotenv import dotenv_values
from flask import Flask, jsonify, redirect, request
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from pymongo import MongoClient

app = Flask(__name__)
environment = dotenv_values()
app_db = MongoClient(environment.get("MONGO_URI"))[environment.get("DB_NAME")]
credential_collection = app_db["credentials"]
SCOPES = [
    "https://www.googleapis.com/auth/classroom.courses.readonly",
    "https://www.googleapis.com/auth/classroom.student-submissions.me.readonly",
]
flow = InstalledAppFlow.from_client_secrets_file(
    client_secrets_file="credentials.json",
    scopes=SCOPES,
    redirect_uri="http://127.0.0.1:5000/oauth/google/callback",
)


def precheck():
    if (
        environment.get("MONGO_URI") is not None
        and environment.get("DB_NAME") is not None
    ):
        return True
    else:
        print("missing environment variables")
        sys.exit()


def check_credential(**kwargs):
    cred = kwargs.get("credential")
    json_string = kwargs.get("json")
    credential = (
        cred
        if (cred is not None)
        else Credentials.from_authorized_user_info(info=json.loads(json_string))
    )
    if credential.valid:
        credential_collection.delete_many({})
        credential_collection.insert_one({"token": credential.to_json()})
        return True
    elif credential.expired and credential.refresh_token:
        credential.refresh(Request())
        return check_credential(credential=credential)
    else:
        return False


def get_credential():
    token = credential_collection.find_one({})["token"]
    if check_credential(json=token):
        return Credentials.from_authorized_user_info(
            info=json.loads(token), scopes=SCOPES
        )


def build_service():
    return build(serviceName="classroom", version="v1", credentials=get_credential())


def get_courses(**kwargs):
    course_id = kwargs.get("id")
    if course_id:
        try:
            return build_service().courses().get(id=course_id).execute()
        except HttpError:
            return "invalid course id"
    return build_service().courses().list().execute().get("courses", [])


@app.route("/login")
def login():
    auth_url = flow.authorization_url()[0]
    return redirect(auth_url)


@app.route("/logout")
def logout():
    credential_collection.delete_many({})
    return "logged out"


@app.route("/oauth/google/callback")
def callback():
    try:
        flow.fetch_token(authorization_response=request.url.replace("http", "https"))
        if check_credential(credential=flow.credentials):
            return "authenticated"
        return "invalid credentials"
    except HttpError as error:
        print(error)
        return "error fetching credentials from url, check logs"
    except Exception as error:
        print(error)
        return "encountered unknown error, check logs"


@app.route("/api/get_courses")
def api_get_courses():
    course_id = dict(request.args).get("id")
    if course_id is not None:
        return get_courses(id=course_id)
    return jsonify(get_courses())


if __name__ == "__main__":
    precheck()
    app.run(host="0.0.0.0")
