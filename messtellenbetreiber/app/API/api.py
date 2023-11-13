from app import app


@app.route('/getcounter/<counter_id>', methods=['GET'])
def get_counter(counter_id):
    return "Hello World!"