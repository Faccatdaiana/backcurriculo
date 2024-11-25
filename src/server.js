const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const xss = require('xss'); 
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const db = require('./db'); 
const app = express();
const csrf = require('csrf');
const tokens = new csrf(); //TOKEN




// DOMPurify
const window = (new JSDOM('')).window;
const purify = DOMPurify(window);

app.use(bodyParser.json());
app.use(cors());

// Função de validação 
function validarCurriculo(req, res, next) {
  const { nome, email, experienciaProfissional } = req.body;

  if (!nome || !email || !experienciaProfissional) {
    return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
  }

  // XSS p evitar scripts
  req.body.nome = xss(req.body.nome);
  req.body.email = xss(req.body.email);
  req.body.telefone = xss(req.body.telefone || '');
  req.body.enderecoWeb = xss(req.body.enderecoWeb || '');
  
  // DOMPurify para limpar algum dado malicioso
  req.body.experienciaProfissional = purify.sanitize(experienciaProfissional);

  next();
}

// Rota para enviar o token CSRF para o frontend
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = tokens.create('secret_key');  // Gerar o token 
  console.log('Token CSRF gerado:', csrfToken);
  res.json({ csrfToken });  // Enviar o token como resposta
});


// Função de middleware para verificar o token
function verificarCsrf(req, res, next) {
  const tokenEnviado = req.body._csrf;  
  if (!tokens.verify('secret_key', tokenEnviado)) {
    return res.status(403).json({ message: 'Token CSRF inválido' });
  }
  next();
}

// Rota para cadastrar o currículo
app.post('/api/curriculos', verificarCsrf, validarCurriculo, async (req, res) => {
  const { nome, telefone, email, enderecoWeb, experienciaProfissional } = req.body;

  // Logando o token CSRF recebido
  console.log('Token CSRF recebido:', req.body._csrf);  // Corrigido para acessar o token no corpo da requisição

  try {
    const novoCurriculo = await db.one(
      `INSERT INTO curriculos (nome, telefone, email, endereco_web, experiencia_profissional) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [nome, telefone, email, enderecoWeb, experienciaProfissional]
    );
    res.status(201).json(novoCurriculo);
  } catch (error) {
    console.error('Erro ao cadastrar currículo:', error);
    res.status(500).json({ message: 'Erro ao cadastrar currículo', error: error.message });
  }
});





// Todos os currículos
app.get('/api/curriculos', async (req, res) => {
  try {
    const curriculos = await db.any('SELECT * FROM curriculos');
    res.json(curriculos);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao listar currículos', error: error.message });
  }
});

// Currículo específico
app.get('/api/curriculos/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id); 
    if (isNaN(id)) {
      return res.status(400).json({ message: 'ID inválido' });
    }
    const curriculo = await db.oneOrNone('SELECT * FROM curriculos WHERE id = $1', [id]);
    if (curriculo) {
      // experiência profissional antes de enviar ao cliente
      curriculo.experiencia_profissional = purify.sanitize(curriculo.experiencia_profissional);
      res.json(curriculo);
    } else {
      res.status(404).json({ message: 'Currículo não encontrado' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar currículo', error: error.message });
  }
});

// Inicia o servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
