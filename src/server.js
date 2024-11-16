const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const xss = require('xss');
const db = require('./db'); 
const app = express();

app.use(bodyParser.json());
app.use(cors());

// Função de validação
function validarCurriculo(req, res, next) {
  const { nome, email, experienciaProfissional } = req.body;

  if (!nome || !email || !experienciaProfissional) {
    return res.status(400).json({ message: 'Campos obrigatórios não preenchidos' });
  }

  req.body.nome = xss(req.body.nome);
  req.body.email = xss(req.body.email);
  req.body.telefone = xss(req.body.telefone || '');
  req.body.enderecoWeb = xss(req.body.enderecoWeb || '');
  req.body.experienciaProfissional = xss(req.body.experienciaProfissional);

  next();
}

// Cadastrar currículo
app.post('/api/curriculos', validarCurriculo, async (req, res) => {
  const { nome, telefone, email, enderecoWeb, experienciaProfissional } = req.body;
  try {
    const novoCurriculo = await db.one(
      `INSERT INTO curriculos (nome, telefone, email, endereco_web, experiencia_profissional) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [nome, telefone, email, enderecoWeb, experienciaProfissional]
    );
    res.status(201).json(novoCurriculo);
  } catch (error) {
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
