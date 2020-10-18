from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
import datetime
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from tensorflow.keras import layers, models
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import pickle
from flask_cors import CORS

app = Flask(__name__)
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'root'
# app.config['MYSQL_DB'] = 'mydb'

app.config['MYSQL_HOST'] = 'database-1.czecpljk7iqw.us-west-1.rds.amazonaws.com'
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'XNhope1010'
app.config['MYSQL_DB'] = 'mydb'

mysql = MySQL(app)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)
CORS(app)

with open('tfidf', 'rb') as fp:
    item_list = pickle.load(fp)
folder_list = ['alt.atheism', 'comp.graphics', 'comp.os.ms-windows.misc', 'comp.sys.ibm.pc.hardware',
               'comp.sys.mac.hardware', 'comp.windows.x', 'misc.forsale', 'rec.autos', 'rec.motorcycles',
               'rec.sport.baseball', 'rec.sport.hockey', 'sci.crypt', 'sci.electronics', 'sci.med', 'sci.space',
               'soc.religion.christian', 'talk.politics.guns', 'talk.politics.mideast', 'talk.politics.misc',
               'talk.religion.misc']

number_nodes = 512
model = models.Sequential()
model.add(layers.Dense(number_nodes, input_dim=75000, activation='relu'))
model.add(layers.Dropout(0.5))
for i in range(0, 4):
    model.add(layers.Dense(number_nodes, input_dim=number_nodes, activation='relu'))
    model.add(layers.Dropout(0.5))
model.add(layers.Dense(20, activation='softmax'))
model.compile(loss='sparse_categorical_crossentropy',
              optimizer='adam',
              metrics=['accuracy'])
model.load_weights('weight_010.hdf5')


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    cur = mysql.connection.cursor()
    cur.execute('SELECT * from user where username = "' + username + '"')
    data = cur.fetchall()
    if len(data) == 0:
        return jsonify({"msg": "username not exist"}), 400

    if not check_password_hash(data[0][1], password):
        return jsonify({"msg": "wrong password"}), 400
    first_name = data[0][2]
    middle_name = data[0][3]
    last_name = data[0][4]
    email = data[0][5]
    phone = data[0][6]
    address = data[0][7]
    occupation = data[0][8]
    # Identity can be any data that is json serializable
    # access_token = create_access_token(identity=username)
    # return jsonify(access_token=access_token), 200
    expires = datetime.timedelta(seconds=120)
    token = create_access_token(username, expires_delta=expires)
    return jsonify({'token': token, 'username': username, 'first_name': first_name, 'middle_name': middle_name,
                    'last_name': last_name, 'email': email, 'phone': phone, 'address': address,
                    'occupation': occupation}), 201


# Using the expired_token_loader decorator, we will now call
# this function whenever an expired but otherwise valid access
# token attempts to access an endpoint
@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'status': 401,
        'sub_status': 42,
        'msg': 'The {} token has expired'.format(token_type)
    }), 401


# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/create-dev-token', methods=['POST'])
@jwt_required
def create_dev_token():
    username = get_jwt_identity()
    expires = datetime.timedelta(seconds=120)
    token = create_access_token(username, expires_delta=expires)
    return jsonify({'token': token}), 201


@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    username = request.json.get('username', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    password = request.json.get('password', None)
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    first_name = request.json.get('first_name', None)
    middle_name = request.json.get('middle_name', None)
    last_name = request.json.get('last_name', None)
    email = request.json.get('email', None)
    if not email:
        return jsonify({"msg": "Missing email parameter"}), 400
    phone = request.json.get('phone', None)
    address = request.json.get('address', None)
    occupation = request.json.get('occupation', None)

    hashed_password = generate_password_hash(password)

    cur = mysql.connection.cursor()

    cur.execute('SELECT username from user where username = "' + username + '"')
    data = cur.fetchall()
    # print(data)
    if len(data) != 0:
        return jsonify({"msg": "username already exist"}), 400
    cur.execute('SELECT email from user where email = "' + email + '"')
    data = cur.fetchall()
    # print(data)
    if len(data) != 0:
        return jsonify({"msg": "email already exist"}), 400

    cur.execute(
        "INSERT INTO user (username,password,first_name,middle_name,last_name, email,phone,address,occupation)"
        "VALUES(%s, %s, %s, %s, %s, %s, %s, %s ,%s)",
        (username, hashed_password, first_name, middle_name, last_name, email, phone, address, occupation))
    mysql.connection.commit()
    # mysql.connection.close()
    return jsonify(msg='success'), 200


@app.route('/upload', methods=['POST'])
@jwt_required
def upload_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        return jsonify(msg='No file key'), 400
    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify(msg='No selected file'), 400

    test_list = [file.read()]
    tfidf = TfidfVectorizer(max_features=75000)
    test_data_tfidf = tfidf.fit_transform(test_list).toarray()
    names = tfidf.get_feature_names()
    result = np.zeros((1, 75000))
    for i in range(len(item_list)):
        for j in range(len(names)):
            if item_list[i] == names[j]:
                result[0, i] = test_data_tfidf[0, j]
    predicted = model.predict(result)
    return jsonify(msg=folder_list[np.argmax(predicted, axis=1)[0]]), 200


@app.route('/update', methods=['POST'])
@jwt_required
def update_password():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    password = request.json.get('password', None)
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    hashed_password = generate_password_hash(password)
    current_user = get_jwt_identity()
    cur = mysql.connection.cursor()
    cur.execute('UPDATE user SET password = "' + hashed_password + '" where username = "' + current_user + '"')
    mysql.connection.commit()
    # mysql.connection.close()
    return jsonify(msg='success'), 200


@app.route('/all', methods=['GET'])
def public_test():
    return jsonify(msg='You have connected to the server'), 200

# if __name__ == '__main__':
#     app.run()
# app.run(host='0.0.0.0', debug=True)
# app.run(host="localhost", port=5001, debug=True)
