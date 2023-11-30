from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import openai
import mysql.connector
import os
import secrets
import bcrypt

from dotenv import load_dotenv

load_dotenv()

# MySQL 연결 설정
mydb = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    user=os.getenv('DB_ID'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_TABLE')
)

mycursor = mydb.cursor()


# 사용자 생성 함수
def create_user(username, password):
    sql = "INSERT INTO users (username, password) VALUES (%s, %s)"
    hash_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
    val = (username, hash_pw)
    mycursor.execute(sql, val)
    mydb.commit()


# 사용자 인증 함수
def authenticate_user(username, password):
    sql = "SELECT password FROM users WHERE username = %s"
    val = (username,)
    mycursor.execute(sql, val)
    result = mycursor.fetchone()
    if result is None:
        return False
    pw = str(result[0])
    return bcrypt.checkpw(password.encode('utf8'), pw.encode('utf8'))


openai.api_key = os.getenv("API_KEY")
# load_dotenv('env/data.env')
# print(os.getenv('OPENAI_API_KEY'))

history_message = []


def format_chat_history(chat_history):
    formatted_messages = ""
    for message in chat_history:
        if message["role"] == "user":
            formatted_messages += f'<div class="user"> USER : {message["content"]}</div>'
        elif message["role"] == "assistant":
            formatted_messages += f'<div class="assistant"> UDOG : {message["content"]}</div>'
    return formatted_messages


# GPT-3 엔진 선택
model_engine = "gpt-3.5-turbo"


# OpenAI API를 호출하여 대화를 생성하는 함수
def generate_chat(question):
    history_message.append({"role": "user", "content": question})
    completions = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=history_message
    )
    message = completions.choices[0].message.to_dict()
    answer = message["content"].strip()

    history_message.append(message)
    return answer


app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/index')
def index():
    return render_template('index.html')


# 정적 파일 경로 설정
@app.route('/static/<path:filename>')
def serve_static(filename):
    return app.send_static_file(filename)


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login2', methods=['POST'])
def login2():
    username = request.form['username']
    password = request.form['password']

    authenticated = authenticate_user(username, password)

    if authenticated:
        session['logged_in'] = True
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error='Login failed. Please check your username and password.')


# 대시보드 라우트 - 로그인이 필요한 페이지
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        username = session['username']
        return render_template('dashboard.html', username=username)
    else:
        return redirect(url_for('login'))


# 로그아웃 라우트
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/userjoin')
def userjoin():
    return render_template('userjoin.html')


@app.route('/join', methods=['POST'])
def join_post():
    username = request.form['username']
    password = request.form['password']
    create_user(username, password)
    return render_template('join_result.html', result='가입되었습니다.')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/chat2', methods=['POST'])
def chat2():
    message = request.form['message']
    history_message.append({"role": "user", "content": message})
    completions = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=history_message
    )
    message = completions.choices[0].message.to_dict()
    answer = message["content"].strip()

    history_message.append(message)
    # JSON 형식으로 응답
    response = {'question': message['content'], 'answer': answer, 'chat_history': format_chat_history(history_message)}
    return jsonify(response)


@app.route('/chat', methods=['GET'])
def chat():
    return render_template('dashboard.html', chat_history=format_chat_history(history_message))


if __name__ == '__main__':
    app.run(debug=True)
