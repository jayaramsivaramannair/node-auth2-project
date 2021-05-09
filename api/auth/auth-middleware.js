const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")
const Users = require("../users/users-model")

const restricted = async (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
  try {
    const token = req.headers.authorization

    if (!token) {
      return res.status(401).json({
        message: "Token required",
      })
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({
          message: "Token invalid",
        })
      }
      req.token = decoded //This token will be accessible by middlewares downstream
      next()
    })

  } catch (err) {
    next(err)
  }
}

const only = role_name => async (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  try {
    if (!req.token || role_name !== req.token.role_name) {
      return res.status(403).json({
        message: "This is not for you",
      })
    } else {
      next()
    }
  } catch (err) {
    next(err)
  }
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  try {
    const username = req.body.username
    const user = await Users.findBy({ username }).first()

    //If the user does not exist in the database
    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
      })
    } else {
      next()
    }
  } catch (err) {
    next(err)
  }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  const roleName = req.body.role_name.trim()
  if (roleName === 'admin') {
    return res.status(422).json({
      message: "Role name can not be admin",
    })
  } else if (roleName.length > 32) {
    return res.status(422).json({
      message: "Role name can not be longer than 32 chars",
    })
  } else if (!roleName) {
    req.role_name = 'student'
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
