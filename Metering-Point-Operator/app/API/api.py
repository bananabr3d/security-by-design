from app import app, db, csrf


@app.route('/getcounter/<counter_id>', methods=['GET'])
@csrf.exempt
def get_counter(counter_id):

    return "Hello World!"