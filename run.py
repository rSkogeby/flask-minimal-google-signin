from views import app
app.run(debug=True, ssl_context=('./ssl.crt', './ssl.key'))