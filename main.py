from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage
from google.cloud.datastore.query import PropertyFilter

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()



CLIENT_ID = 'HsidxavpfIRnImVNo5dsuyljotaoUq8v'
CLIENT_SECRET = 'kjJhTRpAXuVV1QMiujU8-nR4pbrsdePDJXioN3ElvNOIIwuWpL9Ono89FdR6dv3H'
DOMAIN = 'dev-ijsyhtk5g6y7pkj3.us.auth0.com'

PHOTO_BUCKET='maie-a6-avatars'


ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}
ERROR_409 = {"Error": "Enrollment data is invalid"}


ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


def validate_course(content):
    if 'subject' not in content:
        return False
    if 'number' not in content:
        return False
    if 'title' not in content:
        return False
    if 'term' not in content:
        return False
    if 'instructor_id' not in content:
        return False
    return True

def validate_instructor(content):
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
    instructor_key = client.key('users', content["instructor_id"])
    instructor = client.get(instructor_key)
    if instructor is None:
        return ERROR_400, 400
    if instructor["role"] != "instructor":
        return ERROR_400, 400


@app.route('/')
def index():
    return "Please navigate to /users/login to use this API"


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

@app.route('/users/login', methods=['POST'])
def user_login():
    content = request.get_json()
    if 'username' not in content or 'password' not in content:
        return ERROR_400, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'

    try:
        r = requests.post(url, json=body, headers=headers)
        return {'token' : r.json()['id_token']}, 200
    except:
        return ERROR_401, 401


@app.route('/users', methods=['GET'])
def users():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    users = list(query.fetch())
    print (len(users))
    if users[0]["role"] != "admin":
        return ERROR_403, 403
    
    query = client.query(kind="users")
    results = list(query.fetch())
    for e in results:
        e["id"] = e.key.id
        
    return jsonify(results), 200


@app.route("/users/<int:user_id>" , methods=['GET'])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())
    if user[0].key.id != user_id:
        if user[0]["role"] != "admin":
            return ERROR_403, 403
    user = client.get(client.key('users', user_id))
    
    
    user["id"] = user.key.id
    if user['role'] == 'instructor' or user['role'] == 'student':
        courses = []
        user['courses'] = courses
    return jsonify(user), 200

    
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def store_image(user_id):
    if 'file' not in request.files:
        return ERROR_400, 400
    
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())

    if user[0].key.id != user_id:
        return ERROR_403, 403
    
    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    file_obj.filename = str(user_id) + ".png"
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    
    user_key = client.key('users', user_id)
    user = client.get(user_key)
    user.update({"avatar_url": request.url})
    client.put(user)
    return {"avatar_url": request.url}, 200


@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())

    if user[0].key.id != user_id:
        return ERROR_403, 403
    
    user_key = client.key('users', user_id)
    user = client.get(user_key)
    if 'avatar_url' not in user:
        return ERROR_404, 404
    
    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob = bucket.blob(str(user_id) + ".png")
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    return send_file(file_obj, mimetype='image/x-png', download_name=str(user_id) + ".png")


@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401

    query = client.query(kind="users")
    query.add_filter('sub', '=', payload["sub"])
    user = list(query.fetch())

    if user[0].key.id != user_id:
        return ERROR_403, 403

    user_key = client.key('users', user_id)
    user = client.get(user_key)
    if 'avatar_url' not in user:
        return ERROR_404, 404

    storage_client = storage.Client()
    bucket = storage_client.bucket(PHOTO_BUCKET)
    blob = bucket.blob(str(user_id) + ".png")
    blob.delete()
    del user['avatar_url']
    client.put(user)
    return '', 204


@app.route('/courses', methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())
    if user[0]["role"] != "admin":
        return ERROR_403, 403
    
    content = request.get_json()
    if not validate_course(content):
        return ERROR_400, 400
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
    instructor_key = client.key('users', content["instructor_id"])
    instructor = client.get(instructor_key)
    if instructor is None:
        return ERROR_400, 400
    if instructor["role"] != "instructor":
        return ERROR_400, 400
    
    new_course = datastore.Entity(key=client.key('courses'))
    new_course.update({"instructor_id": content["instructor_id"],
                   "subject": content["subject"],
                   "number": content["number"],
                   "title": content["title"],
                   "term": content["term"]})
    client.put(new_course)
    new_course["id"] = new_course.key.id
    new_course["self"] = request.url + "/" + str(new_course.key.id)
    return jsonify(new_course), 201


@app.route('/courses', methods=['GET'])
def get_courses():
    offset = request.args.get('offset')

    if offset is None:
        offset = 0
    else:
        offset = int(offset)
    
    query = client.query(kind="courses")
    query.order = ["subject"]
    c_iterator = query.fetch(limit=3, offset=offset)
    pages = c_iterator.pages
    courses = list(next(pages))
    for c in courses:
        c["id"] = c.key.id
        c["self"] = request.url_root + "courses/" + str(c.key.id)
    results = {"courses": courses,
               "next": request.url + "?limit=" + str(3) + "&offset=" + str(int(offset) + int(3))}
    return jsonify(results), 200


@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if course is None:
        return ERROR_404, 404
    course["id"] = course.key.id
    course["self"] = request.url
    return jsonify(course), 200

@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())
    if user[0]["role"] != "admin":
        return ERROR_403, 403

    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if course is None:
        return ERROR_403, 403
    
    try:
        content = request.get_json()
    except:
        content = {}

    if 'subject' not in content:
        content['subject'] = course['subject']
    if 'number' not in content:
        content['number'] = course['number']
    if 'title' not in content:
        content['title'] = course['title']
    if 'term' not in content:
        content['term'] = course['term']
    if 'instructor_id' not in content:
        content['instructor_id'] = course['instructor_id']
    
    if "instructor_id" in content:
        query = client.query(kind="users")
        query.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
        instructor_key = client.key('users', content["instructor_id"])
        instructor = client.get(instructor_key)
        if instructor is None:
            return ERROR_400, 400
        if instructor["role"] != "instructor":
            return ERROR_400, 400

    course.update(content)
    course.update({"instructor_id": content["instructor_id"],
                   "subject": content["subject"],
                   "number": content["number"],
                   "title": content["title"],
                   "term": content["term"]})
    client.put(course)
    course["id"] = course.key.id
    course['self'] = request.url
    return jsonify(course), 200

@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())
    if user[0]["role"] != "admin":
        return ERROR_403, 403
    
    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if course is None:
        return ERROR_403, 403
    client.delete(course_key)

    # TODO: Delete all students enrolled in the course
    
    return '', 204


@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def enroll_students(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if course is None:
        return ERROR_403, 403

    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())

    if user[0]['role'] != 'admin' and (user[0].key.id != course['instructor_id']):
        return ERROR_403, 403
    
    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter('role', '=', 'student'))
    students = list(query.fetch())
    students = set([s.key.id for s in students])
    content = request.get_json()

    for student_id in content['add']:
        if student_id in content['remove']:
            return ERROR_409, 409
        if student_id not in students:
            return ERROR_409, 409

    for student_id in content['remove']:
        if student_id not in students:
            return ERROR_409, 409
    
    for student_id in content['add']:
        query = client.query(kind='enrollments')
        query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
        query.add_filter(filter=PropertyFilter('student_id', '=', student_id))
        existing_enrollment = list(query.fetch())
        if len(existing_enrollment) == 0:
            new_enrollment = datastore.Entity(key=client.key('enrollments'))
            new_enrollment.update({"course_id": course_id,
                           "student_id": student_id})
            client.put(new_enrollment)
    
    for student_id in content['remove']:
        query = client.query(kind='enrollments')
        query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
        query.add_filter(filter=PropertyFilter('student_id', '=', student_id))
        existing_enrollment = list(query.fetch())
        if len(existing_enrollment) != 0:
            client.delete(existing_enrollment[0].key)

    return '', 200

@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_enrollments(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    course_key = client.key('courses', course_id)
    course = client.get(course_key)
    if course is None:
        return ERROR_403, 403

    query = client.query(kind='users')
    query.add_filter(filter=PropertyFilter('sub', '=', payload["sub"]))
    user = list(query.fetch())

    if user[0]['role'] != 'admin' and (user[0].key.id != course['instructor_id']):
        return ERROR_403, 403
    
    query = client.query(kind='enrollments')
    query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
    enrollments = list(query.fetch())
    students = []
    for e in enrollments:
        students.append(e['student_id'])
    return jsonify(students), 200


    
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

