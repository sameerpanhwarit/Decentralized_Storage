# cloud route
# @app.route('/cloud', methods=['GET','POST'])
# @login_required_and_verified
# def cloud():
#     if request.method == 'GET':
#         try:
#             user_id = session["user_id"]
#             select_query = "SELECT * FROM files WHERE fileid = %s"
#             cursor.execute(select_query, (user_id,))
#             files = cursor.fetchall()
#             print(files)
#             cursor.execute('SELECT username FROM users WHERE userid = %s', (user_id,))
#             existing_user = cursor.fetchone()
#             username = existing_user[0]
#             return render_template('cloud.html', files=files, username=username)
#         except Exception as e:
#             print(e)
#     return render_template('cloud.html')



@app.route('/starred', methods=['GET','POST'])
def starred():
    if request.method == 'POST':
        pass
    user_id = session["user_id"]
    select_query = "SELECT * FROM files WHERE fileid = %s AND starred = 1"
    cursor.execute(select_query, (user_id,))
    files = cursor.fetchall()
    return render_template('star.html', files=files)
