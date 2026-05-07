import hashlib
import sqlite3

# [취약점 1] 하드코딩된 비밀번호 및 인증키 (CWE-798)
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "admin_password_123!"

def login_user(username, password):
    # [취약점 2] 구식 암호화 알고리즘 사용 - MD5 (CWE-327)
    hashed_pw = hashlib.md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # [취약점 3] SQL 인젝션 (CWE-89) - 사용자 입력을 그대로 쿼리에 조립함
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_pw}'"
    cursor.execute(query)
    
    return cursor.fetchall()

def calculator(user_math_formula):
    # [취약점 4] 위험한 함수 사용 - eval (CWE-94) - 해커가 서버 명령어를 실행할 수 있음
    result = eval(user_math_formula)
    return result

print("서버가 시작되었습니다...")
