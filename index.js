const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const JWT_SECRET = 'clave_secreta_pos_2026';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Conexión a SQLite
const db = new sqlite3.Database('./pos.db', (err) => {
  if (err) console.error('Error:', err.message);
  else console.log('Conectado a la base de datos SQLite.');
});

// Crear tablas e inicializar estructura
db.serialize(() => {
  // Tabla de Usuarios
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      rol TEXT DEFAULT 'cajero'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS categorias (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT UNIQUE NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS productos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      precio REAL NOT NULL,
      stock INTEGER NOT NULL,
      categoria_id INTEGER,
      tipo_promo TEXT DEFAULT 'ninguna',
      promo_cant_min INTEGER DEFAULT 0,
      promo_precio_esp REAL DEFAULT 0,
      promo_porcentaje REAL DEFAULT 0,
      FOREIGN KEY (categoria_id) REFERENCES categorias(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ventas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      total REAL NOT NULL,
      fecha DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS detalle_ventas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      venta_id INTEGER,
      producto_nombre TEXT,
      cantidad INTEGER,
      precio_unitario REAL,
      subtotal REAL,
      FOREIGN KEY (venta_id) REFERENCES ventas(id)
    )
  `);

  // Categorías iniciales
  db.get("SELECT COUNT(*) AS count FROM categorias", (err, row) => {
    if (row && row.count === 0) {
      const categoriasIniciales = [
        "Bebidas gaseosas", "Bebidas Alcohólicas", "Vinos", "Energizantes",
        "Art. Limpieza", "Comestibles secos", "Comestibles heladera", "Fiambres", "Quesos"
      ];
      const stmt = db.prepare("INSERT INTO categorias (nombre) VALUES (?)");
      categoriasIniciales.forEach(cat => stmt.run(cat));
      stmt.finalize();
    }
  });
});

// RUTAS DE AUTENTICACIÓN (LOGIN Y REGISTRO)
app.post('/api/auth/registro', async (req, res) => {
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password) {
    return res.status(400).json({ error: 'Nombre, email y contraseña son obligatorios' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const sql = `INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)`;
    db.run(sql, [nombre, email, passwordHash, rol || 'cajero'], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'El email ya está registrado' });
        }
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ mensaje: 'Usuario creado exitosamente', id: this.lastID });
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al procesar contraseña' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const sql = `SELECT * FROM usuarios WHERE email = ?`;
  db.get(sql, [email], async (err, usuario) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!usuario) return res.status(401).json({ error: 'Usuario no encontrado' });

    const coincide = await bcrypt.compare(password, usuario.password);
    if (!coincide) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      mensaje: 'Login correcto',
      token,
      usuario: { id: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol }
    });
  });
});

// RUTAS CATEGORÍAS
app.get('/api/categorias', (req, res) => {
  db.all("SELECT * FROM categorias ORDER BY nombre ASC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/categorias', (req, res) => {
  const { nombre } = req.body;
  if (!nombre) return res.status(400).json({ error: "El nombre es requerido" });

  db.run("INSERT INTO categorias (nombre) VALUES (?)", [nombre], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, nombre });
  });
});

app.delete('/api/categorias/:id', (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM categorias WHERE id = ?", [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ mensaje: "Categoría eliminada", cambios: this.changes });
  });
});

// RUTAS PRODUCTOS
app.get('/api/productos', (req, res) => {
  const sql = `
    SELECT p.*, c.nombre AS categoria 
    FROM productos p 
    LEFT JOIN categorias c ON p.categoria_id = c.id
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/productos', (req, res) => {
  const { nombre, precio, stock, categoria_id, tipo_promo, promo_cant_min, promo_precio_esp, promo_porcentaje } = req.body;
  const sql = `INSERT INTO productos 
    (nombre, precio, stock, categoria_id, tipo_promo, promo_cant_min, promo_precio_esp, promo_porcentaje) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

  db.run(sql, [
    nombre, 
    Number(precio), 
    Number(stock), 
    categoria_id ? Number(categoria_id) : null,
    tipo_promo || 'ninguna',
    Number(promo_cant_min) || 0,
    Number(promo_precio_esp) || 0,
    Number(promo_porcentaje) || 0
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, mensaje: "Producto creado con éxito" });
  });
});

app.put('/api/productos/:id', (req, res) => {
  const { id } = req.params;
  const { nombre, precio, stock, categoria_id, tipo_promo, promo_cant_min, promo_precio_esp, promo_porcentaje } = req.body;
  const sql = `UPDATE productos SET 
    nombre = ?, precio = ?, stock = ?, categoria_id = ?, 
    tipo_promo = ?, promo_cant_min = ?, promo_precio_esp = ?, promo_porcentaje = ? 
    WHERE id = ?`;

  db.run(sql, [
    nombre, 
    Number(precio), 
    Number(stock), 
    categoria_id ? Number(categoria_id) : null,
    tipo_promo || 'ninguna',
    Number(promo_cant_min) || 0,
    Number(promo_precio_esp) || 0,
    Number(promo_porcentaje) || 0,
    id
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ mensaje: "Producto actualizado" });
  });
});

app.delete('/api/productos/:id', (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM productos WHERE id = ?", id, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ mensaje: "Producto eliminado", cambios: this.changes });
  });
});

// REGISTRAR VENTA
app.post('/api/ventas', (req, res) => {
  const { carrito, totalVenta } = req.body;
  if (!carrito || carrito.length === 0) return res.status(400).json({ error: "Carrito vacío" });

  db.serialize(() => {
    db.run("INSERT INTO ventas (total) VALUES (?)", [totalVenta], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const ventaId = this.lastID;

      const stmtDetalle = db.prepare("INSERT INTO detalle_ventas (venta_id, producto_nombre, cantidad, precio_unitario, subtotal) VALUES (?, ?, ?, ?, ?)");
      const stmtStock = db.prepare("UPDATE productos SET stock = stock - ? WHERE id = ? AND stock >= ?");

      carrito.forEach(item => {
        stmtDetalle.run(ventaId, item.nombre, item.cantidad, item.precioUnitarioOriginal, item.subtotalCalculado);
        stmtStock.run(item.cantidad, item.id, item.cantidad);
      });

      stmtDetalle.finalize();
      stmtStock.finalize((err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ mensaje: "Venta registrada con éxito", ventaId, total: totalVenta });
      });
    });
  });
});

// OBTENER HISTORIAL DE CAJA DIARIA
app.get('/api/ventas/caja', (req, res) => {
  const sql = `
    SELECT v.id, v.total, datetime(v.fecha, 'localtime') as fecha,
           GROUP_CONCAT(d.producto_nombre || ' (x' || d.cantidad || ')', ', ') as items
    FROM ventas v
    LEFT JOIN detalle_ventas d ON v.id = d.venta_id
    GROUP BY v.id
    ORDER BY v.id DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});