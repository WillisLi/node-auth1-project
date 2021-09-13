// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const { checkPasswordLength, checkUsernameFree, checkUsernameExists } = require('./auth-middleware')
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
  const { username, password } = req.body
  const hash = bcrypt.hashSync(password, 8)
  const newUser = { username: username, password: hash }
  Users.add(newUser)
    .then(addedUser => {
      res.status(201).json(addedUser)
    })
    .catch(next);
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, (req, res, next) => {
  const login = req.body;
  Users.findBy(login.username)
    .then(existing => {
      if (existing && bcrypt.compareSync(login.password, existing.password))
        req.session.user = existing;
        res.json({message: `Welcome ${req.body.username}!`})
    })
    .catch(next)
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res) => {
  if (req.session.user) {
    req.session.destroy(err => {
      if (err) {
        res.status(200).json({message: "error logging out"})
      } else {
        res.status(200).json({message: "logged out"})
      }
    });
  } else {
    res.status(200).json({message: "no session"})
  }
})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;