import ipaddress 
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import routeros_api
import config

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Me permite mostrar mensajes flash

# Mi funcion para poder conectar a la API de Mikrotik
def connect_to_mikrotik(username, password):
    connection = routeros_api.RouterOsApiPool(
        config.MIKROTIK_HOST,
        username=username,
        password=password,
        port=config.MIKROTIK_PORT,
        plaintext_login=True
    )
    try:
        api = connection.get_api()
        return api  # Devuelve la instancia de la API
    except Exception as e:
        print(f"Error al conectar a Mikrotik: {e}")  # Imprimir error en consola
        return None  # Si hay algún error


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.clear()
        username = request.form['username']
        password = request.form['password']

        print(f"Intentando iniciar sesión con usuario: {username} y contraseña: {password}")

        api = connect_to_mikrotik(username, password)
        if api:
            session['username'] = username
            session['password'] = password
            print('Inicio de sesión exitoso')
            return redirect(url_for('interfaces'))  # Redirigir a interfaces.html
        else:
            flash('Authentication failed: invalid username or password.', 'danger')
            return redirect(url_for('login'))  # Redirigir de vuelta al login en caso de fallar la autenticacion

    return render_template('login.html')  # Solo para el metodo GET





# Funciones para las interfaces

@app.route('/interfaces')
def interfaces():
    return render_template('interfaces.html')

@app.route('/api/interfaces')
def get_interfaces():
    api = connect_to_mikrotik(session.get('username'), session.get('password'))

    if api:
        try:
            # Obtener los datos de las interfaces de Mikrotik
            interfaces = api.get_resource('/interface').get()
            # Crear una lista con los datos relevantes para la tabla
            data = []
            for interface in interfaces:
                data.append({
                    'comment': interface.get('comment', ''),
                    'name': interface.get('name'),
                    'type': interface.get('type'),
                    'actual_mtu': interface.get('actual-mtu', ''),
                    'l2mtu': interface.get('l2mtu', ''),
                    'tx': interface.get('tx-byte', '0 bps'),
                    'rx': interface.get('rx-byte', '0 bps'),
                    'tx_packet_ps': interface.get('tx-packet', '0 p/s'),
                    'rx_packet_ps': interface.get('rx-packet', '0 p/s'),
                    'fp_tx': interface.get('fp-tx-byte', '0 bps'),
                    'fp_rx': interface.get('fp-rx-byte', '0 bps'),
                    'fp_tx_packet_ps': interface.get('fp-tx-packet', '0 p/s'),
                    'fp_rx_packet_ps': interface.get('fp-rx-packet', '0 p/s'),
                })
            return jsonify(data)  # Devolver los datos en formato JSON
        except Exception as e:
            print(f"Error al obtener interfaces: {e}")
            return jsonify({'error': 'Error al obtener interfaces'}), 500

    return jsonify({'error': 'Credenciales incorrectas'}), 401



# Funciones para los usuarios
@app.route('/usuarios')
def usuarios():
    return render_template('usuarios.html')

@app.route('/api/usuarios')
def get_usuarios():
    api = connect_to_mikrotik(session.get('username'), session.get('password'))

    if api:
        try:
            usuarios = api.get_resource('/user').get()
            print("Usuarios obtenidos:", usuarios)  # Para depurar

            data = []
            for usuario in usuarios:
                data.append({
                    'name': usuario.get('name'),
                    'group': usuario.get('group'),
                    'comment': usuario.get('comment', ''),
                    'last_logged_in': usuario.get('last-logged-in', ''),
                    'allowed_address': usuario.get('allowed-address', ''),
                })

            return jsonify(data)
        except Exception as e:
            print(f"Error al obtener usuarios: {e}")
            return jsonify({'error': 'Error al obtener usuarios'}), 500

    return jsonify({'error': 'Credenciales incorrectas'}), 401

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form.get('name', '').strip()  # Usamos .get para evitar KeyError
    password = request.form.get('password', '').strip()
    comment = request.form.get('comment', '').strip()
    group = request.form.get('group', '').strip()
    allowed_address = request.form.get('allowed_address', '').strip()
    enable = 'enable' in request.form  # Verifica si el checkbox está marcado

    print(f"Agregando usuario: {username}, Grupo: {group}, Permisos: {allowed_address}, Activo: {enable}")  # Para depuración por consola

    if not username or not password or not group:
        flash('El nombre de usuario, la contraseña y el grupo son obligatorios.', 'danger')
        return redirect(url_for('usuarios'))

    api = connect_to_mikrotik(session.get('username'), session.get('password'))

    if api:
        try:
            # Crear el nuevo usuario en MikroTik
            user_data = {
                'name': username,
                'password': password,
                'comment': comment,
                'group': group,
                'disabled': 'yes' if not enable else 'no'  # Usar 'yes'/'no' en lugar de True/False
            }
            if allowed_address:  # Solo agregar el campo si no está vacío
                user_data['allowed_address'] = allowed_address

            api.get_resource('/user').add(**user_data)  # Desempaqueta el diccionario como argumentos
            flash('Usuario agregado exitosamente', 'success')
            return redirect(url_for('usuarios'))  # Redirigir de vuelta a la lista de usuarios
        except Exception as e:
            print(f"Error al agregar el usuario: {e}")
            return jsonify({'error': str(e)}), 500

    flash('No se pudo conectar a MikroTik', 'danger')
    return redirect(url_for('usuarios'))



@app.route('/eliminar_usuario', methods=['POST'])
def eliminar_usuario():
    username = request.form.get('username')
    if not username:
        return jsonify({'error': 'El nombre de usuario es necesario'}), 400

    api = connect_to_mikrotik(session.get('username'), session.get('password'))

    if api:
        try:
            # Obtener el recurso del usuario específico
            user_resource = api.get_resource('/user')
            
            # Buscar el usuario por nombre
            usuario = user_resource.get(name=username)
            
            if not usuario:
                return jsonify({'error': 'Usuario no encontrado'}), 404

            # Eliminar el usuario usando el identificador correcto
            user_resource.remove(id=usuario[0].get('id'))  # Usar el 'id' del usuario
            return jsonify({'success': 'Usuario eliminado exitosamente'}), 200
        except Exception as e:
            print(f"Error al eliminar el usuario: {e}")
            return jsonify({'error': 'Error al eliminar el usuario'}), 500

    return jsonify({'error': 'Credenciales incorrectas'}), 401




@app.route('/ip_addresses')
def ip_addresses():
    return render_template('ip_addresses.html')

@app.route('/api/ip_addresses')
def get_ip_addresses():
    api = connect_to_mikrotik(session.get('username'), session.get('password'))

    if api:
        try:
            # Obtener las direcciones IP de Mikrotik
            ip_addresses = api.get_resource('/ip/address').get()

            # Crear una lista con los datos relevantes para la tabla
            data = []
            for ip in ip_addresses:
                data.append({
                    'address': ip.get('address'),
                    'network': ip.get('network'),
                    'interface': ip.get('interface'),
                })

            return jsonify(data)  # Devolver los datos en formato JSON
        except Exception as e:
            print(f"Error al obtener direcciones IP: {e}")
            return jsonify({'error': 'Error al obtener direcciones IP'}), 500

    return jsonify({'error': 'Credenciales incorrectas'}), 401

# Función para calcular la red a partir de una dirección IP
def calcular_red(address):
    try:
        ip_network = ipaddress.ip_network(address, strict=False)
        return str(ip_network.network_address)
    except ValueError as e:
        print(f"Error al calcular la red: {e}")
        return None

# Ruta para agregar una nueva dirección IP
@app.route('/add_ip', methods=['POST'])
def add_ip():
    api = connect_to_mikrotik(session.get('username'), session.get('password'))
    
    if api:
        try:
            data = request.json
            address = data.get('address')
            interface = data.get('interface')
            
            # Validar que se proporcionó una dirección
            if not address or not interface:
                return jsonify({'success': False, 'message': 'Faltan datos necesarios'}), 400

            # Calcular la red si no se proporciona
            network = calcular_red(address)

            # Añadir la dirección IP en Mikrotik
            ip_data = {
                'address': address,
                'interface': interface,
                'network': network
            }
            api.get_resource('/ip/address').add(**ip_data)

            return jsonify({'success': True})
        except Exception as e:
            print(f"Error al agregar la IP: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500

    return jsonify({'success': False, 'message': 'Credenciales incorrectas'}), 401


@app.route('/eliminar_ip', methods=['POST'])
def eliminar_ip():
    data = request.get_json()  # Obtener el cuerpo de la solicitud JSON
    ip_address = data.get('address')  # Obtener la dirección IP del JSON
    if not ip_address:
        return jsonify({'error': 'La dirección IP es necesaria'}), 400

    api = connect_to_mikrotik(session.get('username'), session.get('password'))

    if api:
        try:
            ip_resource = api.get_resource('/ip/address')
            ip = ip_resource.get(address=ip_address)

            if not ip:
                return jsonify({'error': 'Dirección IP no encontrada'}), 404

            ip_resource.remove(id=ip[0].get('id'))  # Eliminar la IP usando el 'id'
            return jsonify({'success': 'Dirección IP eliminada exitosamente'}), 200
        except Exception as e:
            print(f"Error al eliminar la IP: {e}")
            return jsonify({'error': 'Error al eliminar la IP'}), 500

    return jsonify({'error': 'Credenciales incorrectas'}), 401










@app.route('/queues')
def queues():
    return render_template('queues.html')


@app.route('/add_queue', methods=['POST'])
def add_queue():
    data = request.json  # Asegúrate de recibir el JSON correctamente
    
    try:
        # Asegúrate de que los datos se manejen correctamente aquí
        enable_queue = data.get('enableQueue')
        comment = data.get('comment')
        name = data.get('name')
        target = data.get('target')
        dst = data.get('dst')
        max_upload = data['maxLimit']['upload']  # Accediendo correctamente a la estructura
        max_download = data['maxLimit']['download']
        # Aquí deberías hacer algo con estos datos, como enviar a la API de MikroTik
        
        # Ejemplo para agregar la queue en MikroTik
        api = connect_to_mikrotik(session.get('username'), session.get('password'))
        if api:
            api.get_resource('/queue/simple').add(
                name=name,
                target=target,
                max_limit=f"{max_upload}/{max_download}",
                comment=comment
            )
            return jsonify({'success': True}), 200
        else:
            return jsonify({'error': 'No se pudo conectar a MikroTik'}), 500
    except Exception as e:
        print(f"Error al agregar la queue: {e}")  # Para depuración
        return jsonify({'error': 'Error al agregar la queue'}), 500




if __name__ == '__main__':
    app.run(debug=True)