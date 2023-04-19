from io import BytesIO
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode
from os import urandom
from flask import Flask, request, jsonify, render_template, send_file, flash, url_for, redirect
from hashlib import md5

app = Flask(__name__)


def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]


def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = urandom(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
    finished = False
    
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))


def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(bytes(x for x in chunk))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    password = request.form['password']
    file = request.files['file']
    filename = file.filename
    in_file = file.read()
    out_file = BytesIO()
    encrypt(BytesIO(in_file), out_file, password)
    out_file.seek(0)
    return send_file(out_file, attachment_filename=f'encrypted_{filename}', as_attachment=True)


password = '12345'


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    password = request.form['password']
    file = request.files['file']
    filename = file.filename
    in_file = file.read()
    out_file = BytesIO()
    decrypt(BytesIO(in_file), out_file, password)
    out_file.seek(0)
    return send_file(out_file, attachment_filename=f'decrypted_{filename}', as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
