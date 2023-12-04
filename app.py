from flask import Flask, render_template, url_for, request, session, redirect,jsonify, flash,get_flashed_messages,send_file, abort
import mysql.connector
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from encrypt import hash_password,check_password
from gen_otp import generateOTP
from functools import wraps
import ipfshttpclient
from Encrypt_data import encrypt, decrypt
import datetime
from io import BytesIO


app = Flask(__name__)
app.secret_key = 'sameerpanhwar112'

static_aes_key = b'ThisIsAStaticKey32Bytes123456789'
static_nonce = b'sameerpanhwar_nonce'

client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="distributed_system"
)
cursor = db.cursor()

def login_required_and_verified(route_func):
    @wraps(route_func)
    def decorated_route(*args, **kwargs):
        if 'user_id' in session:
            user_id = session['user_id']
            cursor.execute('SELECT verified FROM users WHERE userid = %s', (user_id,))
            result = cursor.fetchone()

            if result is not None and result[0]:  # User exists and is verified
                return route_func(*args, **kwargs)
            else:
                flash('Please verify your account', 'error')
                return redirect(url_for('verify'))
        else:
            flash('Please log in to access the dashboard.', 'error')
            return redirect(url_for('login'))

    return decorated_route



def is_user_verified():
    user_id = session.get('user_id')
    if user_id is not None:
        cursor.execute('SELECT verified FROM users WHERE userid = %s', (user_id,))
        result = cursor.fetchone()
        return result and result[0]
    return False


def delete_otp(user_id):
    cursor.execute("DELETE FROM otp_table WHERE id = %s", (user_id,))
    db.commit()


@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('index.html')
    else:
        return redirect('dashboard')

#signup route
@app.route('/signup', methods=["GET", "POST"])
def signup():
    if 'user_id' in session:
        return redirect('dashboard')
    if request.method == "POST":
        data = request.get_json()

        first = data.get('first')
        last = data.get('last')
        email = data.get('email')
        password = data.get('password')
        # password = hash_password(password)
        username = first.capitalize()+ " "+last.capitalize()
        try:
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                return jsonify({'error': 'User already exists', 'redirect': ''})
            
            else:
                cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)',
                (username, email,password))
                db.commit()

                user_id = cursor.lastrowid

            # Generate OTP
                otp = generateOTP(email)

            # Insert OTP into the db table
                cursor.execute('INSERT INTO otp_table (id, otp_code) VALUES (%s, %s)', (user_id, otp))
                db.commit()

                print(user_id, otp)

                session['user_id'] = user_id
                session['username']=username
                session['email']=email

                redirect_url = url_for('verify')
                return jsonify({'redirect': redirect_url})
        except Exception as e:
            print("An error occurred: ", str(e))

    return render_template('signup.html')

#verify user
def verifyUser(user_id, entered_otp):
    cursor.execute('SELECT id FROM otp_table WHERE id = %s AND otp_code = %s', (user_id, entered_otp))
    result = cursor.fetchone()
    return result is not None

#verification route
@app.route("/verify", methods=['GET','POST'])
def verify():
    if 'user_id' in session:
        user_id = session['user_id']
        if is_user_verified():
            return redirect("dashboard")

        if request.method == "POST":
            n1=request.form['n1']
            n2=request.form['n2']
            n3=request.form['n3']
            n4=request.form['n4']
            otp = int(n1+n2+n3+n4)
            if verifyUser(user_id, otp):
                cursor.execute('UPDATE users SET verified = TRUE WHERE userid = %s', (user_id,))
                db.commit()
                delete_otp(user_id)
                return redirect(url_for('dashboard'))
        else:
            email = session['email']
            return render_template('verification.html', email=email)
    else:
        return redirect('signup')
    

#login route 
@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        if is_user_verified():  # Check for verification
            return redirect('dashboard')
        return redirect('verify')
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # password = password.encode('utf-8')
        try:
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                print(existing_user)
                storedPassword = existing_user[3]
                session['user_id'] = existing_user[0]
                print(storedPassword)
                if password == storedPassword:
                    return redirect('dashboard')
                else:
                    flash('Incorrect password', 'error')
                    return render_template("login.html", email=email)
            else:
                flash('User not Exist', 'error')
                return render_template("login.html", email=email)

        except:
            pass


    else:
        return render_template('login.html')

#logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


#dashboard route
@app.route('/dashboard')
@login_required_and_verified
def dashboard():
    user_id = session['user_id']
    cursor.execute('SELECT username FROM users WHERE userid = %s', (user_id,))
    existing_user = cursor.fetchone()
    username = existing_user[0]

    return render_template("dashboard.html", username=username)


# @app.route('/upload', methods=['POST'])
# @login_required_and_verified
# def upload():
#     if 'uploadfile' in request.files:
#         file = request.files['uploadfile']
#         if file.filename != '':
#             file_name = file.filename
#             file_type = file.content_type
#             file_type = file_type.split("/")[-1]
#             file_content = file.read()

#             file_size_mb = len(file_content) / (1024 * 1024)
#             current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#             user_id = session["user_id"]
#             print(f"File name: {file_name}, Size: {file_size_mb} MB, Date: {current_date}, Type: {file_type}")
#             file_stream = BytesIO(file_content)

 
#             file.seek(0)

#             try:
#                 response = client.add(file_stream)
#                 hash = response['Hash']


#                 insert_query = "INSERT INTO files (fileid,filename, filehash, filetype, filesize,date) VALUES (%s, %s, %s, %s, %s, %s)"
#                 data = (user_id, file_name, hash, file_type, file_size_mb,current_date)
#                 cursor.execute(insert_query, data)
#                 db.commit()
#                 print(f"File uploaded Successfully - {hash}")
#                 return redirect('dashboard')
#             except Exception as e:
#                 print(e)
#     return redirect('dashboard')


@app.route('/upload', methods=['POST'])
@login_required_and_verified
def upload():
    if 'uploadfile' in request.files:
        file = request.files['uploadfile']
        if file.filename != '':
            file_name = file.filename
            file_type = file.content_type
            file_type = file_type.split("/")[-1]
            file_content = file.read()

            file_size_mb = len(file_content) / (1024 * 1024)
            current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user_id = session["user_id"]
            print(f"File name: {file_name}, Size: {file_size_mb} MB, Date: {current_date}, Type: {file_type}")
            file.seek(0)

            try:
                file_stream = encrypt(file_content)
                response = client.add(file_stream)
                hash = response['Hash']


                insert_query = "INSERT INTO files (fileid,filename, filehash, filetype, filesize,date) VALUES (%s, %s, %s, %s, %s, %s)"
                data = (user_id, file_name, hash, file_type, file_size_mb,current_date)
                cursor.execute(insert_query, data)
                db.commit()
                print(f"File uploaded Successfully - {hash}")
                return redirect('dashboard')
            except Exception as e:
                print(e)
    return redirect('dashboard')


@app.route('/cloud', methods=['GET', 'POST'])
@login_required_and_verified
def cloud():
    if request.method == 'GET':
        try:
            user_id = session["user_id"]

            # Retrieve files of currently logged-in user a JOIN
            select_query = "SELECT files.* FROM files JOIN users ON files.fileid = users.userid WHERE files.fileid = %s AND files.deleted = 0"
            cursor.execute(select_query, (user_id,))
            files = cursor.fetchall()
            print(files)

            cursor.execute('SELECT username FROM users WHERE userid = %s', (user_id,))
            existing_user = cursor.fetchone()
            username = existing_user[0]

            return render_template('cloud.html', files=files, username=username)
        except Exception as e:
            print(e)

    return render_template('cloud.html')


@app.route('/delete/<file_hash>', methods=['GET'])
@login_required_and_verified
def delete(file_hash):
    try:
        update_query = "UPDATE files SET deleted = 1 WHERE filehash = %s"
        cursor.execute(update_query, (file_hash,))
        db.commit()

        select_query = "SELECT * FROM files WHERE filehash = %s"
        cursor.execute(select_query, (file_hash,))
        file_details = cursor.fetchone()
        print("printing details", file_details)
        file_id, user_id, filename, filehash, fileformat, filesize, upload_date, deleted, starred = file_details
        print(user_id, filehash)
        
        trash_insert_query = """
            INSERT INTO trash (file_id, file_name, file_hash, file_type, file_size, deleted_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        deleted_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = (user_id, filename, filehash, fileformat, filesize,deleted_at)
        cursor.execute(trash_insert_query, data)
        db.commit()

        return redirect(url_for('cloud'))
    except Exception as e:
        print(e)
        return redirect(url_for('dashboard'))


@app.route('/permanent_delete/<file_hash>', methods=['GET'])
@login_required_and_verified
def permanent_delete(file_hash):
    try:
        print(file_hash)
        delete_query = "DELETE FROM trash WHERE file_hash = %s"
        cursor.execute(delete_query, (file_hash,))
        db.commit()
        
        delete_query2 = "DELETE FROM files WHERE filehash = %s"
        cursor.execute(delete_query2, (file_hash,))
        db.commit()

        print("Deleted")
        return redirect(url_for('cloud'))
    except Exception as e:     
        print(e)
        return redirect(url_for('dashboard'))
    
# @app.route('/download/<file_hash>', methods=['GET'])
# @login_required_and_verified
# def download(file_hash):
#     try:
#         select_query = "SELECT * FROM files WHERE filehash = %s"
#         cursor.execute(select_query, (file_hash,))
#         file_details = cursor.fetchone()

#         if file_details:
#             ipfs_hash = file_details[3]
#             try:
#                 response = client.cat(ipfs_hash)
#             except Exception as ipfs_error:
#                 print(f"IPFS Connection Error: {ipfs_error}")
#                 abort(500, "IPFS Internal Server Error")

#             if response:
#                 real_name = file_details[2]
#                 file_type = file_details[4]
#                 file_extension = file_type

#                 temp_file_path = os.path.join(f'{real_name}')
#                 with open(temp_file_path, 'wb') as temp_file:
#                     temp_file.write(response)

#                 headers = {
#                     'Content-Disposition': f'attachment; filename={real_name}.{file_extension}'
#                 }

#                 return send_file(
#                     temp_file_path,
#                     as_attachment=True,
#                     download_name=real_name,
#                     mimetype=file_type,
#                 )
#             else:
#                 abort(404, "File not found on IPFS")
#         else:
#             abort(404, "File details not found in the database")
#     except Exception as e:
#         print(f"Internal Server Error: {e}")
#         abort(500, "Internal Server Error")


@app.route('/download/<file_hash>', methods=['GET'])
@login_required_and_verified
def download(file_hash):
    try:
        select_query = "SELECT * FROM files WHERE filehash = %s"
        cursor.execute(select_query, (file_hash,))
        file_details = cursor.fetchone()

        if file_details:
            ipfs_hash = file_details[3]
            try:
                response = client.cat(ipfs_hash)
                decrypt_file = decrypt(response)
            except Exception as ipfs_error:
                print(f"IPFS Connection Error: {ipfs_error}")
                abort(500, "IPFS Internal Server Error")

            if response:
                real_name = file_details[2]
                file_type = file_details[4]
                file_extension = file_type

                temp_file_path = os.path.join(f'{real_name}')
                with open(temp_file_path, 'wb') as temp_file:
                    temp_file.write(decrypt_file)

                headers = {
                    'Content-Disposition': f'attachment; filename={real_name}.{file_extension}'
                }

                return send_file(
                    temp_file_path,
                    as_attachment=True,
                    download_name=real_name,
                    mimetype=file_type,
                )
            else:
                abort(404, "File not found on IPFS")
        else:
            abort(404, "File details not found in the database")
    except Exception as e:
        print(f"Internal Server Error: {e}")
        abort(500, "Internal Server Error")


@app.route('/star/<file_hash>', methods=['GET'])
@login_required_and_verified
def star(file_hash):
    try:
        print(file_hash)
        cursor.execute("SELECT starred FROM files WHERE filehash = %s", (file_hash,))
        file_status = cursor.fetchone()[0]
        new_starred_value = 1 if file_status == 0 else 0
        cursor.execute("UPDATE files SET starred = %s WHERE filehash = %s", (new_starred_value, file_hash))
        db.commit()
        print("updated successfully")
        return redirect(url_for('cloud'))

    except:
        return redirect(url_for('cloud'))
    

@app.route('/starred', methods=['GET','POST'])
@login_required_and_verified
def starred():
    if request.method == 'POST':
        pass
    user_id = session["user_id"]
    select_query = """
        SELECT files.*, users.username
        FROM files
        JOIN users ON files.fileid = users.userid
        WHERE files.fileid = %s AND files.starred = 1 AND files.deleted = 0
    """
    cursor.execute(select_query, (user_id,))
    files = cursor.fetchall()
    username = files[0][-1] if files else None
    return render_template('star.html', files=files, username=username)

    


@app.route('/trash', methods=['GET'])
@login_required_and_verified
def trash():
    if request.method == 'POST':
        pass
    user_id = session["user_id"]
    select_query = """
        SELECT trash.*, users.username
        FROM trash
        JOIN users ON trash.file_id = users.userid
        WHERE trash.file_id = %s
    """
    cursor.execute(select_query, (user_id,))
    files = cursor.fetchall()
    print("Trash files", files)
    username = files[0][-1] if files else None
    return render_template('trash.html', files=files, username=username)


@app.route('/restore/<file_hash>', methods=['GET'])
@login_required_and_verified
def restore(file_hash):
    try:
        update_query = "UPDATE files SET deleted = 0 WHERE filehash = %s"
        cursor.execute(update_query, (file_hash,))
        db.commit()

        delete_query = "DELETE FROM trash WHERE file_hash = %s"
        cursor.execute(delete_query, (file_hash,))
        db.commit()

        return redirect(url_for('cloud'))
    except Exception as e:
        print(e)
        return redirect(url_for('dashboard'))
    

if __name__ == '__main__':
    app.run(debug=True)
