# run.py

from app import create_app

app = create_app()

if __name__ == '__main__':
    # 'debug=True' reloads the server on code changes
    # 'host="0.0.0.0"' makes it accessible from your browser
    app.run(debug=True, host="0.0.0.0", port=5000)