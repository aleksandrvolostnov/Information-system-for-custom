from werkzeug.security import generate_password_hash
passwords = ['password1', 'password2', 'password3', 'password4', 'password5']
hashed_passwords = [generate_password_hash(password) for password in passwords]
for i, hashed in enumerate(hashed_passwords):
    print(f"User {i + 1}: {hashed}")