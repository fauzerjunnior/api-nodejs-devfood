const express = require('express');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const cors = require('cors');

const PORT = process.env.PORT || 3333;
const secret = 'devFood@secret';
const expiresIn = '1d';

const server = jsonServer.create();
const router = jsonServer.router('./database/data.json');


server.use(cors());
server.use(express.urlencoded({ extended: true }));
server.use(express.json());
server.use(jsonServer.defaults());

function createToken(payload) {
  return jwt.sign(payload, secret, {
    expiresIn
  })
}

function verifyToken(token) {
  return jwt.verify(token, secret, (err, decode) =>
    decode !== undefined ? decode : err
  );
}

function isAuthenticated({
  email,
  password
}) {
  const userdb = JSON.parse(fs.readFileSync('./database/user.json', 'UTF-8'));

  return (
    userdb.findIndex(
      user => user.email === email && user.password === password
    ) !== -1
  );
}

server.post('/auth/register', (req, res) => {
  const {
    name,
    email,
    password
  } = req.body;

  fs.readFile('./database/user.json', (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({
        status,
        message
      });
      return;
    }

    const users = JSON.parse(data.toString());
    let lastItemID = [];

    if (users.length) {
      lastItemID = users[users.length - 1].id;
    }

    users.push({
      id: lastItemID + 1,
      name,
      email,
      password,
      avatar_url: 'https://i.imgur.com/WFXYVFH.jpg'
    });

    fs.writeFile(
      './database/user.json',
      JSON.stringify(users),
      (err) => {
        if (err) {
          const status = 401;
          const message = err;
          res.status(status).json({
            status,
            message
          });
        }
      }
    );
  });

  res.status(200).json();
});

server.post('/auth/login', (req, res) => {
  const {
    email,
    password
  } = req.body;

  if (!isAuthenticated({
      email,
      password
    })) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({
      status,
      message
    });
    return;
  }

  const accessToken = createToken({
    email,
    password
  });

  const userdb = JSON.parse(fs.readFileSync('./database/user.json', 'UTF-8'));
  const { id, name, avatar_url } = userdb.filter(item => item.email === email)[0];
  
  res.status(200).json({
    accessToken,
    user: {
      id,
      name, 
      email,
      avatar_url
    }
  });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(' ')[0] !== 'Bearer'
  ) {
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({
      status,
      message
    });
    return;
  }

  try {
    const verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = 'Access token not provided';
      res.status(status).json({
        status,
        message
      });
      return;
    }

    next();
  } catch (err) {
    const status = 401;
    const message = 'Error accessToken is revoked';
    res.status(status).json({
      status,
      message
    });
  }
});

server.use(router);
server.listen(PORT, () => {
  console.log(`🔥  API is running`);
});

