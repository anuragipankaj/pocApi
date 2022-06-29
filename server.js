const express = require('express')
const jwtDecode = require('jwt-decode')
const jsonwebtoken = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const randToken = require('rand-token');
const cors = require('cors')
const jwt = require('express-jwt');
const axios = require('axios');


var tokens = {};
var users = {
  "test1@g.com": {
    email: "test1@g.com",
    password: 'p1',

  },
  "test2@g.com": {
    email: "test2@g.com",
    password: 'p2',

  }
}
const app = express()
const port = 3000

const SECRET = 'changeme';


app.use(cors())
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const generateToken = user => {
  const token = jsonwebtoken.sign({
    sub: user.email,
    email: user.email,
    aud: 'api.example.com',
    iss: 'api.example.com',
  }, SECRET, {
    expiresIn: '30000',
    algorithm: 'HS256'
  })

  return token
}

const createRefreshToken = user => {
  var refreshToken = getRefreshToken();
  tokens[refreshToken] = user;
}


const hashPassword = password => {
  return new Promise((resolve, reject) => {
    bcrypt.genSalt(10, (err, salt) => {
      if (err) reject(err)
      bcrypt.hash(password, salt, (err, hash) => {
        if (err) reject(err)
        resolve(hash)
      })
    })
  })
}

const checkPassword = (password, hash) => bcrypt.compare(password, hash)

const getRefreshToken = () => randToken.uid(256)

// API ENDPOINTS 

app.post('/api/login', async (req, res) => {
  console.log("api hit")
  const { email, password } = req.body
  const user = users[email]
  if (!user) {
    return res.status(401).json({
      message: 'User not found!'
    })
  }
  const isPasswordValid = await checkPassword(password, user.password)

  if (!isPasswordValid) {
    return res.status(401).json({
      message: 'Invalid password!'
    })
  }
  const accessToken = generateToken(user)
  const decodedAccessToken = jwtDecode(accessToken)
  const accessTokenExpiresAt = decodedAccessToken.exp
  const refreshToken = getRefreshToken(user)



  tokens[refreshToken] = { refreshToken, user: user.email };
  //  const storedRefreshToken = new Token({ refreshToken, user: user._id })
  // await storedRefreshToken.save()

  res.json({
    accessToken,
    expiresAt: accessTokenExpiresAt,
    refreshToken
  })
})

app.post('/api/register', async (req, res) => {

  const { email, password, firstName, lastName } = req.body

  const hashedPassword = await hashPassword(password)
  const userData = {
    email: email,
    firstName: firstName,
    lastName: lastName,
    password: hashedPassword,
  }

  const existingUser = users[email]

  if (existingUser) {
    return res.status(400).json({
      message: 'Email already exists'
    })
  }

  users[email] = userData
  savedUser = userData
  if (savedUser) {
    const accessToken = generateToken(savedUser);
    const decodedToken = jwtDecode(accessToken);
    const expiresAt = decodedToken.exp;

    return res.status(200).json({
      message: 'User created successfully',
      accessToken,
      expiresAt,
      refreshToken: createRefreshToken(savedUser),
    })
  }
})


app.post('/api/refreshToken', async (req, res) => {
  const { refreshToken } = req.body
  try {
    const user = tokens[refreshToken]

    if (!user) {
      return res.status(401).json({
        message: 'Invalid token'
      })
    }

    const existingUser = users[tokens[refreshToken].user]

    if (!existingUser) {
      return res.status(401).json({
        message: 'Invalid token'
      })
    }

    const token = generateToken(existingUser)
    return res.json({ accessToken: token })
  } catch (err) {
    return res.status(500).json({ message: 'Could not refresh token' })
  }
})

const attachUser = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res
      .status(401)
      .json({ message: 'Authentication invalid' });
  }
  try {
    const decodedToken = jwtDecode(token.slice(7));

    if (!decodedToken) {
      return res.status(401).json({
        message: 'There was a problem authorizing the request'
      });
    } else {
      req.user = decodedToken;
      next();
    }
  } catch {
    return res.status(401).json({
      message: 'Exception : There was a problem authorizing the request'
    });
  }
};

app.use(attachUser);

const requireAuth = jwt({
  secret: SECRET,
  audience: 'api.example.com',
  issuer: 'api.example.com',
  algorithms: ['HS256']
});


app.get('/api/cat', requireAuth, async (req, res) => {
  const response = await axios.get('https://cataas.com/cat',
    { responseType: "arraybuffer" })
  let raw = Buffer.from(response.data).toString('base64');
  res.send("data:" + response.headers["content-type"] + ";base64," + raw);

})

async function connect() {
  var keys = Object.keys(users)
  for (var i = 0; i < keys.length; i++) {
    var email = keys[i];
    var userData = users[email];
    if (userData) {
      userData.password = await hashPassword(userData.password)
      users[email] = userData;
    }
  }
  app.listen(port);
  console.log(`Server listening on port ${port}`);
}

connect();
