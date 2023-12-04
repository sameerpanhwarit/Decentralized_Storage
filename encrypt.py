import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def check_password(input_password, hashed):
    return bcrypt.checkpw(input_password.encode('utf-8'), hashed.endcode('utf-8'))