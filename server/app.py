from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_cors import CORS

# defining flask as app
app = Flask(__name__, static_folder='frontend', template_folder='templates')

# cors config
CORS(app)

# home api
@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)