from app import app, db


@app.route('/getcounter/<counter_id>', methods=['GET'])
def get_counter(counter_id):

    return "Hello World!"