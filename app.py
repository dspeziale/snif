from flask import Flask, render_template, abort
import os

# Crea l'applicazione Flask
app = Flask(__name__)

# Configurazione
app.config['SECRET_KEY'] = 'your-secret-key-here'


@app.route('/')
def index():
    """Homepage con dashboard"""
    # Dati mock per la dashboard
    stats = {
        'new_orders': 150,
        'bounce_rate': 53,
        'user_registrations': 44,
        'unique_visitors': 65
    }

    # Dati per i grafici
    chart_data = {
        'sales_data': [
            {'name': 'Digital Goods', 'data': [28, 48, 40, 19, 86, 27, 90]},
            {'name': 'Electronics', 'data': [65, 59, 80, 81, 56, 55, 40]}
        ],
        'categories': ['2023-01-01', '2023-02-01', '2023-03-01', '2023-04-01',
                       '2023-05-01', '2023-06-01', '2023-07-01']
    }

    return render_template('index.html', stats=stats, chart_data=chart_data)


@app.route('/widgets')
def widgets():
    """Pagina widgets"""
    return render_template('widgets.html')


@app.route('/forms')
def forms():
    """Pagina forms"""
    return render_template('forms.html')


@app.route('/tables')
def tables():
    """Pagina tables"""
    return render_template('tables.html')


@app.route('/about')
def about():
    """Pagina about"""
    return render_template('about.html')


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    # Assicurati che la cartella templates esista
    if not os.path.exists('templates'):
        os.makedirs('templates')
        os.makedirs('templates/errors')

    if not os.path.exists('static'):
        os.makedirs('static')
        os.makedirs('static/css')
        os.makedirs('static/js')
        os.makedirs('static/img')

    app.run(debug=True, host='0.0.0.0', port=5000)