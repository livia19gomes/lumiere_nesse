from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime, timedelta
from main import app, con
import jwt

app = Flask(__name__)
CORS(app, origins=["*"])

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id, email):
    payload = {'id_usuario': user_id, 'email':email}
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def remover_bearer(token):
    if token.startswith('Bearer '):
        return token[len('Bearer '):]
    else:
        return token

def validar_senha(senha):
    if len(senha) < 8:
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres"}), 400

    if not re.search(r"[!@#$%¨&*(),.?\":<>{}|]", senha):
        return jsonify({"error": "A senha deve conter pelo menos um símbolo especial"}), 400

    if not re.search(r"[A-Z]", senha):
        return jsonify({"error": "A senha deve conter pelo menos uma letra maiúscula"}), 400

    if len(re.findall(r"\d", senha)) < 2:
        return jsonify({"error": "A senha deve conter pelo menos dois números"}), 400

    return True

def verificar_adm(id_cadastro):
    cur = con.cursor()
    cur.execute("SELECT tipo FROM cadastro WHERE id_cadastro = ?", (id_cadastro,))
    tipo = cur.fetchone()

    if tipo and tipo[0] == 'adm':
        return True
    else:
        return False

@app.route('/cadastro', methods=['POST'])
def cadastro_usuario():
    if not request.is_json:
        return jsonify({"error": "É necessário enviar JSON válido"}), 400

    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON vazio"}), 400

    # campos básicos obrigatórios (tipo NÃO está aqui)
    campos_basicos = ['nome', 'email', 'telefone', 'senha']
    faltando = [campo for campo in campos_basicos if not data.get(campo)]
    if faltando:
        return jsonify({"error": f"Campos obrigatórios faltando: {', '.join(faltando)}"}), 400

    nome = data['nome']
    email = data['email']
    telefone = data['telefone']
    senha = data['senha']
    tipo = data.get('tipo', 'usuario').lower()   # se não vier, assume "usuario"
    categoria = data.get('categoria')

    # regra: profissional precisa de categoria
    if tipo == 'profissional' and not categoria:
        return jsonify({"error": "Campo 'categoria' é obrigatório para profissionais"}), 400

    # se for adm ou usuario, categoria não é necessária
    if tipo in ['adm', 'usuario']:
        categoria = None

    # valida senha
    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({"error": "Este usuário já foi cadastrado!"}), 400

    senha_hashed = generate_password_hash(senha)

    cur.execute(
        "INSERT INTO CADASTRO (NOME, EMAIL, TELEFONE, SENHA, CATEGORIA, TIPO, ATIVO) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (nome, email, telefone, senha_hashed, categoria, tipo, True)
    )
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'nome': nome,
            'email': email,
            'tipo': tipo,
            'categoria': categoria
        }
    }), 200

@app.route('/cadastro', methods=['GET'])
def lista_cadastro():
        cur = con.cursor()
        cur.execute("SELECT id_cadastro, nome, email, telefone, senha, categoria, tipo, ativo FROM cadastro")
        usuarios = cur.fetchall()
        usuarios_dic = []

        for usuario in usuarios:
            usuarios_dic.append({
            'id_cadastro': usuario[0],
            'nome': usuario[1],
            'email': usuario[2],
            'telefone': usuario[3],
            'senha': usuario[4],
            'categoria': usuario[5],
            'tipo': usuario[6]
            })

        return jsonify(mensagem='Lista de usuarios', usuarios=usuarios_dic)

@app.route('/cadastro/<int:id>', methods=['DELETE'])
def deletar_Usuario(id):
    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE id_cadastro = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Usuario não encontrado"}), 404

    cur.execute("DELETE FROM cadastro WHERE id_cadastro = ?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuario excluído com sucesso!",
        'id_cadastro': id
    })

@app.route('/cadastro/<int:id>', methods=['PUT'])
def editar_usuario(id):
    cur = con.cursor()
    cur.execute("SELECT id_cadastro, nome, email, telefone, senha, categoria, tipo, ativo FROM CADASTRO WHERE id_cadastro = ?", (id,))
    usuarios_data = cur.fetchone()

    if not usuarios_data:
        cur.close()
        return jsonify({"error": "Usuário não foi encontrado"}), 404

    email_armazenado = usuarios_data[2]
    tipo_armazenado = usuarios_data[6]
    ativo_armazenado = usuarios_data[7]

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    telefone = data.get('telefone')
    senha = data.get('senha')
    categoria = data.get('categoria')
    tipo = data.get('tipo')
    ativo = data.get('ativo')

    # validação de senha
    if senha is not None:
        senha_check = validar_senha(senha)
        if senha_check is not True:
            return senha_check
        senha = generate_password_hash(senha)
    else:
        senha = usuarios_data[4]  # mantém a senha antiga

    if tipo is None:
        tipo = tipo_armazenado
    if ativo is None:
        ativo = ativo_armazenado

    if email_armazenado != email:
        cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({"message": "Este usuário já foi cadastrado!"}), 400

    cur.execute(
        "UPDATE cadastro SET nome = ?, email = ?, telefone = ?, senha = ?, categoria = ?, tipo = ?, ativo = ? WHERE id_cadastro = ?",
        (nome, email, telefone, senha, categoria, tipo, ativo, id)
    )

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário atualizado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'categoria': categoria,
            'tipo': tipo,
            'ativo': ativo
        }
    })

tentativas = {}

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    print(email, senha)

    if not email or not senha:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    # Simulando busca no banco
    cur = con.cursor()
    cur.execute("SELECT senha, tipo, id_cadastro, ativo, nome, telefone FROM CADASTRO WHERE email = ?", (email,))
    usuario = cur.fetchone()
    cur.close()

    if not usuario:
        return jsonify({"error": "Usuário ou senha inválidos"}), 401

    senha_armazenada, tipo, id_cadastro, ativo, nome, telefone = usuario

    if not ativo:
        return jsonify({"error": "Usuário inativo"}), 401

    if check_password_hash(senha_armazenada, senha):
        # Login OK, gera token
        token = generate_token(id_cadastro, email)
        return jsonify({
            "message": "Login realizado com sucesso!",
            "usuario": {
                "id_cadastro": id_cadastro,
                "nome": nome,
                "email": email,
                "telefone": telefone,
                "tipo": tipo,
                "token": token
            }
        })

    else:
        # Controle de tentativas
        if id_cadastro not in tentativas:
            tentativas[id_cadastro] = 0

        if tipo != 'adm':
            tentativas[id_cadastro] += 1
            if tentativas[id_cadastro] >= 3:
                cur = con.cursor()
                cur.execute("UPDATE CADASTRO SET ATIVO = false WHERE id_cadastro = ?", (id_cadastro,))
                con.commit()
                cur.close()
                return jsonify({"error": "Usuário inativado por excesso de tentativas."}), 403

        return jsonify({"error": "Senha incorreta"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Token de autenticação necessário"}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        return jsonify({"message": "Logout realizado com sucesso!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

codigos_temp = {}

def parse_datetime(data_str, hora_str):
    """Converte data + hora em datetime, aceitando com ou sem segundos."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(f"{data_str} {hora_str}", fmt)
        except ValueError:
            continue
    raise ValueError(f"Formato inválido: {data_str} {hora_str}")

@app.route('/servicos', methods=['POST'])
def cadastrar_servico():
    try:
        data = request.get_json()

        id_profissional = data.get('id_profissional')
        descricao = data.get('descricao')
        duracao = data.get('duracao')
        preco = data.get('preco')
        data_servico = data.get('data_servico')
        horario_inicio = data.get('horario_inicio')

        print("Dados recebidos:", data)

        if not all([id_profissional, descricao, duracao, preco, data_servico, horario_inicio]):
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        cur = con.cursor()

        # Seleciona serviços existentes do mesmo profissional na mesma data
        cur.execute("""
            SELECT HORARIO_INICIO, DURACAO
            FROM SERVICOS
            WHERE ID_PROFISSIONAL = ? 
              AND DATA_SERVICO = ?
        """, (id_profissional, data_servico))

        servicos_existentes = cur.fetchall()
        print("Serviços existentes:", servicos_existentes)

        # Calcula início e fim do novo serviço
        novo_inicio = parse_datetime(data_servico, horario_inicio)
        novo_fim = novo_inicio + timedelta(minutes=int(duracao))

        # Verifica conflito de horários
        for serv in servicos_existentes:
            existente_inicio = parse_datetime(data_servico, serv[0])
            existente_fim = existente_inicio + timedelta(minutes=int(serv[1]))

            if (novo_inicio < existente_fim) and (novo_fim > existente_inicio):
                cur.close()
                return jsonify({"error": "Já possuí um serviço agendado nesse horário!"}), 400

        print("Inserindo novo serviço...")
        # Insere o novo serviço
        cur.execute("""
            INSERT INTO SERVICOS (ID_PROFISSIONAL, DESCRICAO, DURACAO, PRECO, DATA_SERVICO, HORARIO_INICIO)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (id_profissional, descricao, duracao, preco, data_servico, horario_inicio))

        con.commit()
        cur.close()

        return jsonify({"message": "Serviço cadastrado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servicos', methods=['GET'])
def listar_servicos():
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT ID_SERVICO, ID_PROFISSIONAL, DESCRICAO, DURACAO, PRECO, DATA_SERVICO, HORARIO_INICIO
            FROM SERVICOS
            ORDER BY DATA_SERVICO, HORARIO_INICIO
        """)
        servicos = cur.fetchall()
        cur.close()

        lista = []
        for s in servicos:
            lista.append({
                "id_servico": s[0],
                "id_profissional": s[1],
                "descricao": s[2],
                "duracao": s[3],
                "preco": s[4],
                "data_servico": str(s[5]),
                "horario_inicio": str(s[6])
            })

        return jsonify(lista), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servicos/<int:id_servico>', methods=['PUT'])
def editar_servico(id_servico):
    try:
        data = request.get_json()

        id_profissional = data.get('id_profissional')
        descricao = data.get('descricao')
        duracao = data.get('duracao')
        preco = data.get('preco')
        data_servico = data.get('data_servico')
        horario_inicio = data.get('horario_inicio')

        print("Dados recebidos para edição:", data)

        if not all([id_profissional, descricao, duracao, preco, data_servico, horario_inicio]):
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        cur = con.cursor()

        # Seleciona serviços existentes do mesmo profissional na mesma data, excluindo o serviço que está sendo editado
        cur.execute("""
            SELECT ID_SERVICO, HORARIO_INICIO, DURACAO
            FROM SERVICOS
            WHERE ID_PROFISSIONAL = ? 
              AND DATA_SERVICO = ?
              AND ID_SERVICO <> ?
        """, (id_profissional, data_servico, id_servico))

        servicos_existentes = cur.fetchall()
        print("Serviços existentes (excluindo o atual):", servicos_existentes)

        # Calcula início e fim do serviço atualizado
        novo_inicio = parse_datetime(data_servico, horario_inicio)
        novo_fim = novo_inicio + timedelta(minutes=int(duracao))

        # Verifica conflito de horários
        for serv in servicos_existentes:
            existente_inicio = parse_datetime(data_servico, serv[1])
            existente_fim = existente_inicio + timedelta(minutes=int(serv[2]))

            if (novo_inicio < existente_fim) and (novo_fim > existente_inicio):
                cur.close()
                return jsonify({"error": "Já possuí um serviço agendado nesse horário!"}), 400

        print("Atualizando serviço...")
        # Atualiza o serviço
        cur.execute("""
            UPDATE SERVICOS
            SET ID_PROFISSIONAL = ?, DESCRICAO = ?, DURACAO = ?, PRECO = ?, DATA_SERVICO = ?, HORARIO_INICIO = ?
            WHERE ID_SERVICO = ?
        """, (id_profissional, descricao, duracao, preco, data_servico, horario_inicio, id_servico))

        con.commit()
        cur.close()

        return jsonify({"message": "Serviço atualizado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

