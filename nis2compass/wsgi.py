import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('NIS2_PORT', 8090)),
        debug=os.getenv('NIS2_DEBUG', 'false').lower() == 'true',
    )
